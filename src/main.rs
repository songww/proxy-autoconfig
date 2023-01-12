use std::path::{Path, PathBuf};

use adblock::filters::network::{FilterPart, NetworkFilter, NetworkFilterMask, NetworkMatchable};
use adblock::lists::{parse_filter, ParseOptions, ParsedFilter};
use base64::prelude::{Engine as _, BASE64_STANDARD as decoder};
use clap::Parser;
use reqwest as request;
use serde::{Deserialize, Serialize, Serializer};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

static APP_NAME: &'static str = "proxy-autoconfig";
static GFWLIST: &'static str =
    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt";

#[derive(Debug)]
enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L: Serialize, R: Serialize> Serialize for Either<L, R> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Either::Left(ref left) => left.serialize(serializer),
            Either::Right(ref right) => right.serialize(serializer),
        }
    }
}

#[derive(Debug, Serialize)]
struct RuleFilter {
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<Either<String, Vec<String>>>,
}

#[derive(Debug, Serialize)]
struct Rule {
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    filter: RuleFilter,
    mask: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    regex: Option<String>,
    is_regex: bool,
    is_complete_regex: bool,
    is_csp: bool,
    is_redirect: bool,
    is_important: bool,
    is_hostname_anchor: bool,
    is_left_anchor: bool,
    is_right_anchor: bool,
    for_http: bool,
    for_https: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct GFWlist {
    url: Option<String>,
    proxy: Option<String>,
    enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
struct Settings {
    proxies: Option<String>,
    pacfile: Option<PathBuf>,
    gfwlist: Option<GFWlist>,
    template: Option<PathBuf>,
    user_rules: Option<PathBuf>,
}

fn configs() -> Vec<PathBuf> {
    let v = PathBuf::from("config.toml");
    let mut paths = Vec::new();
    if let Some(cfgdir) = dirs::config_dir() {
        paths.push(cfgdir.join(APP_NAME).join(&v));
    }
    paths.push(PathBuf::from("/etc/").join(APP_NAME).join(&v));
    paths
}

fn load_config(path: Option<&Path>) -> anyhow::Result<Settings> {
    if let Some(path) = path {
        return _load_config(path);
    }
    let paths = configs();
    for path in paths.iter() {
        match _load_config(&path) {
            Err(err) => {
                if let Some(err) = err.downcast_ref::<toml::de::Error>() {
                    if let Some((line, col)) = err.line_col() {
                        anyhow::bail!("Syntax error in {:?}:{} at column {}", path, line, col)
                    } else {
                        anyhow::bail!("Can not parse {:?}, invalid toml file.", path);
                    }
                }
                continue;
            }
            Ok(cfg) => return Ok(cfg),
        }
    }
    let mut files = String::new();
    for path in paths.iter() {
        files.push_str(path.to_str().unwrap());
        files.push('\n');
    }
    anyhow::bail!(
        "\"config.toml\" dose not found, please make sure it exists at one of: \n{}",
        files.trim()
    )
}

fn _load_config(path: &Path) -> anyhow::Result<Settings> {
    let cfg = std::fs::read_to_string(path)?;
    toml::from_str(&cfg)
        .map_err(|err| anyhow::anyhow!("Can not load config file: {:?} caused by: {:?}", path, err))
}

trait NetworkFilterExt {
    fn for_http(&self) -> bool;
    fn for_https(&self) -> bool;
    fn first_party(&self) -> bool;
    fn third_party(&self) -> bool;
}

impl NetworkFilterExt for NetworkFilter {
    fn for_http(&self) -> bool {
        self.mask.contains(NetworkFilterMask::FROM_HTTP)
    }
    fn for_https(&self) -> bool {
        self.mask.contains(NetworkFilterMask::FROM_HTTPS)
    }

    fn first_party(&self) -> bool {
        self.mask.contains(NetworkFilterMask::FIRST_PARTY)
    }

    fn third_party(&self) -> bool {
        self.mask.contains(NetworkFilterMask::THIRD_PARTY)
    }
}

trait ToJavaScript {
    fn to_javascript(&self) -> Rule;
}

impl ToJavaScript for NetworkFilter {
    fn to_javascript(&self) -> Rule {
        let (method, pattern) = match self.filter {
            FilterPart::Empty => ("empty", None),
            FilterPart::Simple(ref pattern) => ("simple", Some(Either::Left(pattern.to_string()))),
            FilterPart::AnyOf(ref patterns) => ("any_of", Some(Either::Right(patterns.clone()))),
        };

        let is_regex = self.is_regex();
        let is_complete_regex = self.is_complete_regex();

        Rule {
            hostname: self.hostname.clone(),
            filter: RuleFilter {
                method: method.to_string(),
                pattern,
            },
            mask: self.mask.bits(),
            regex: (is_regex || is_complete_regex).then_some(self.get_regex().to_string()),
            is_regex,
            is_complete_regex,
            is_csp: self.is_csp(),
            is_redirect: self.is_redirect(),
            is_important: self.is_important(),
            is_hostname_anchor: self.is_hostname_anchor(),
            is_left_anchor: self.is_left_anchor(),
            is_right_anchor: self.is_right_anchor(),
            for_http: self.for_http(),
            for_https: self.for_https(),
        }
    }
}

#[derive(clap::Args, Debug)]
struct Serve {
    /// which interface listening on, default is '127.0.0.1'
    #[arg(short, long, default_value = "127.0.0.1")]
    host: String,
    /// which port listening on, default is '1089'
    #[arg(short, long, default_value_t = 1089)]
    port: u16,

    /// build pac file on start.
    #[arg(short, long, default_value_t)]
    build: bool,

    #[command(flatten)]
    build_args: BuildArgs,
}

#[derive(clap::Args, Debug)]
struct Build {
    #[command(flatten)]
    args: BuildArgs,
}

#[derive(clap::Args, Debug)]
struct BuildArgs {
    /// path to config.toml, default is '~/.config/proxy-autoconfig/config.toml'
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Proxy for pac.
    /// such as: "SOCKS 127.0.0.1:1080; DIRECT", Primary proxy is 127.0.0.1:1080, but if the proxy go down,
    ///     automatically start making direct connections.
    /// "PROXY 127.0.0.1:1080" For http(s) proxy.
    /// see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file#return_value_format
    #[arg(long)]
    proxies: Option<String>,

    /// path to store/serve pac file.
    /// default is ~/.local/share/proxy-autoconfig/proxy.pac
    #[arg(short, long)]
    pacfile: Option<PathBuf>,

    /// path to user rules, default is '~/.config/proxy-autoconfig/user-rules.txt'
    #[arg(short, long)]
    user_rules: Option<PathBuf>,

    /// whether to use gfwlist.
    #[arg(long)]
    gfwlist_enabled: bool,
    /// url for fetch gfwlist.
    /// default is: https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
    #[arg(long)]
    gfwlist_url: Option<String>,
    /// use proxy for fetch gfwlist from url.
    #[arg(long)]
    gfwlist_proxy: Option<String>,
}

#[derive(Parser, Debug)] // requires `derive` feature
#[command(author, version, about, long_about = None)]
enum Options {
    Build(Build),
    Serve(Serve),
}

impl Settings {
    fn merge_options(&mut self, args: BuildArgs) {
        if let Some(pacfile) = args.pacfile {
            self.pacfile.replace(pacfile);
        };
        if self.pacfile.is_none() {
            self.pacfile
                .replace(dirs::data_dir().unwrap().join(APP_NAME).join("proxy.pac"));
        }
        if let Some(user_rules) = args.user_rules {
            self.user_rules.replace(user_rules);
        }
        if let Some(proxies) = args.proxies {
            self.proxies.replace(proxies);
        }
        if self.gfwlist.is_none() {
            self.gfwlist = Some(Default::default());
        }
        let gfwlist = self.gfwlist.as_mut().unwrap();
        if let Some(gfwlist_url) = args.gfwlist_url {
            gfwlist.url.replace(gfwlist_url);
        }
        if let Some(gfwlist_proxy) = args.gfwlist_proxy {
            gfwlist.proxy.replace(gfwlist_proxy);
        }
        if args.gfwlist_enabled {
            gfwlist.enabled = true;
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.proxies.is_none() {
            anyhow::bail!("proxies is required.");
        }
        let pacfile = self.pacfile.as_ref().unwrap();
        if pacfile.exists() {
            let metadata = std::fs::metadata(pacfile)?;
            if !metadata.is_file() {
                anyhow::bail!("path of user-rules '{pacfile:?}' is not a normal file or dose not has permissions to read.");
            }
        } else {
            if let Some(p) = pacfile.parent() {
                std::fs::create_dir_all(p)?;
            }
        }

        let cfgs = dirs::config_dir().unwrap().join(APP_NAME);
        if !cfgs.exists() {
            std::fs::create_dir(&cfgs)?;
        }
        if !std::fs::metadata(&cfgs)?.is_dir() {
            anyhow::bail!("config dir {:?} is not dir.", cfgs);
        }

        let data = dirs::data_dir().unwrap().join(APP_NAME);
        if !data.exists() {
            std::fs::create_dir(&data)?;
        }
        if !std::fs::metadata(&data)?.is_dir() {
            anyhow::bail!("data dir {:?} is not dir.", data);
        }

        Ok(())
    }
}

fn _build(settings: &Settings) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    let default_template_path = dirs::config_dir()
        .unwrap()
        .join(APP_NAME)
        .join("proxy.pac.template");
    let template_path = if let Some(ref template) = settings.template {
        if !template.exists() {
            anyhow::bail!(
                "specified template of proxy.pac dose not exists: {:?}",
                template
            );
        }
        template
    } else {
        if !default_template_path.exists() {
            static PROXY_PAC_TEMPLATE: &'static str = include_str!("../proxy.pac.template");
            std::fs::write(&default_template_path, PROXY_PAC_TEMPLATE)?;
        }
        &default_template_path
    };
    let mut template = std::fs::read_to_string(template_path)?.replacen(
        "__PROXIES__",
        settings.proxies.as_ref().unwrap(),
        1,
    );

    let default_user_rule_path = dirs::config_dir()
        .unwrap()
        .join(APP_NAME)
        .join("user-rules.txt");
    let user_rules_path = if let Some(ref user_rules_path) = settings.user_rules {
        user_rules_path
    } else {
        &default_user_rule_path
    };
    if !user_rules_path.exists() {
        warn!("user rules dose not exists: {:?}", user_rules_path);
    }
    info!("loading user rules from {:?}", user_rules_path);
    let user_rules = user_rules(user_rules_path)?;
    let (direct, over_proxy): (Vec<NetworkFilter>, Vec<NetworkFilter>) =
        user_rules.into_iter().partition(|rule| rule.is_exception());

    let mut user_rule_direct = Vec::with_capacity(direct.capacity());
    let mut user_rule_over_proxy = Vec::with_capacity(direct.capacity());

    direct
        .iter()
        .for_each(|rule| user_rule_direct.push(rule.to_javascript()));
    over_proxy
        .iter()
        .for_each(|rule| user_rule_over_proxy.push(rule.to_javascript()));

    template = template
        .replacen(
            "__USER_DIRECT__",
            &serde_json::to_string(&user_rule_direct)?,
            1,
        )
        .replacen(
            "__USER_PROXY__",
            &serde_json::to_string(&user_rule_over_proxy)?,
            1,
        );

    let default_gfwlist_options = GFWlist::default();
    let gfwlist_options = match settings.gfwlist {
        Some(ref opt) => opt,
        None => &default_gfwlist_options,
    };
    if gfwlist_options.enabled {
        let rules = rt.block_on(gfwlist_rules(&gfwlist_options))?;
        let (direct, over_proxy): (Vec<NetworkFilter>, Vec<NetworkFilter>) =
            rules.into_iter().partition(|rule| rule.is_exception());
        let mut gfw_direct = Vec::with_capacity(direct.len());
        let mut gfw_proxy = Vec::with_capacity(over_proxy.len());
        direct.iter().for_each(|rule| {
            gfw_direct.push(rule.to_javascript());
        });
        over_proxy.iter().for_each(|rule| {
            gfw_proxy.push(rule.to_javascript());
        });
        template = template
            .replacen("__GFW_DIRECT__", &serde_json::to_string(&gfw_direct)?, 1)
            .replacen("__GFW_PROXY__", &serde_json::to_string(&gfw_proxy)?, 1);
    } else {
        warn!("gfwlist disabled");
    }

    let pacfile = settings.pacfile.as_ref().unwrap();

    std::fs::write(pacfile, &template)?;

    info!("pac file build succeeded.");

    info!("pac file has been saved to {:?}", pacfile);

    Ok(())
}

async fn gfwlist_rules(gfwlist_options: &GFWlist) -> anyhow::Result<Vec<NetworkFilter>> {
    let mut c = request::ClientBuilder::new()
        .tcp_nodelay(true)
        .deflate(true)
        .user_agent("curl/7.87.0");
    if let Some(ref proxy) = gfwlist_options.proxy {
        let proxy = request::Proxy::all(proxy)?;
        c = c.proxy(proxy);
    }
    let c = c.build()?;

    let url: &str = if let Some(ref url) = gfwlist_options.url {
        url
    } else {
        GFWLIST
    };

    let resp = c.get(url).send().await?;
    let capacity: usize = if let Some(length) = resp.content_length() {
        length as usize
    } else {
        300_000
    };
    let mut gfwlist = Vec::with_capacity(capacity);
    let text = resp.text().await?;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        gfwlist.extend_from_slice(line.trim().as_bytes());
        assert!(gfwlist.len() < capacity);
    }

    let decoded = decoder.decode(&gfwlist)?;

    let gfwlist = String::from_utf8(decoded)?;

    let parse_options = ParseOptions::default();

    let rules: Vec<NetworkFilter> = gfwlist
        .lines()
        .skip(1)
        .map(|line| parse_filter(line, false, parse_options))
        .filter_map(|filter| match filter {
            Ok(ParsedFilter::Network(network)) => Some(network),
            _ => None,
        })
        .collect();
    Ok(rules)
}

fn user_rules<P: AsRef<Path>>(path: P) -> anyhow::Result<Vec<NetworkFilter>> {
    let parse_options = ParseOptions::default();

    let user_rules = std::fs::read_to_string(path.as_ref())?;

    let rules: Vec<NetworkFilter> = user_rules
        .lines()
        .skip(1)
        .map(|line| parse_filter(line, false, parse_options))
        .filter_map(|filter| match filter {
            Ok(ParsedFilter::Network(network)) => Some(network),
            _ => None,
        })
        .collect();

    Ok(rules)
}

fn _serve(host: &str, port: u16, pacfile: &Path) -> anyhow::Result<()> {
    use poem::{
        endpoint::{EndpointExt, StaticFileEndpoint},
        listener::TcpListener,
        middleware::Tracing,
        IntoResponse, Route, Server,
    };
    let app = Route::new().at(
        "/proxy.pac",
        StaticFileEndpoint::new(pacfile)
            .and_then(|resp| async {
                Ok(resp.with_content_type("application/x-ns-proxy-autoconfig"))
            })
            .with(Tracing),
    );

    info!("Serving proxy.pac from: {:?}", pacfile);
    let listen = format!("{host}:{port}");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async { Server::new(TcpListener::bind(listen)).run(app).await })?;
    Ok(())
}

fn main() {
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::INFO)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let opt = Options::parse();
    match opt {
        Options::Build(build) => {
            let mut settings =
                load_config(build.args.config.as_ref().map(|v| v.as_path())).unwrap();
            settings.merge_options(build.args);
            settings.validate().unwrap();
            _build(&settings).unwrap();
        }
        Options::Serve(serve) => {
            let mut settings =
                load_config(serve.build_args.config.as_ref().map(|v| v.as_path())).unwrap();
            settings.merge_options(serve.build_args);
            settings.validate().unwrap();
            if serve.build {
                _build(&settings).unwrap();
            }
            _serve(&serve.host, serve.port, &settings.pacfile.unwrap()).unwrap();
        }
    }
}
