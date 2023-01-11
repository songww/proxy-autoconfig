use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use adblock::filters::network::{FilterPart, NetworkFilter, NetworkFilterMask, NetworkMatchable};
use adblock::lists::{parse_filter, ParseOptions, ParsedFilter};
use base64::prelude::{Engine as _, BASE64_STANDARD as decoder};
use reqwest as request;
use serde_derive::Deserialize;

mod generator;

#[derive(Debug, Default, Deserialize)]
struct GFWlist {
    url: Option<String>,
    proxy: Option<String>,
    enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
struct Settings {
    proxies: String,
    gfwlist: Option<GFWlist>,
}

fn configs() -> Vec<PathBuf> {
    vec![PathBuf::from("config.toml")]
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
    fn to_javascript(&self) -> String;
}

impl ToJavaScript for NetworkFilter {
    fn to_javascript(&self) -> String {
        let hostname = if let Some(ref hostname) = self.hostname {
            format!("\"{hostname}\"")
        } else {
            "null".to_string()
        };
        let (method, pattern) = match self.filter {
            FilterPart::Empty => ("empty", "null".to_string()),
            FilterPart::Simple(ref pattern) => ("simple", format!("\"{pattern}\"")),
            FilterPart::AnyOf(ref patterns) => {
                let mut val = String::from('[');
                for pattern in patterns {
                    val.push_str(&format!(r#""{pattern}","#));
                }
                val.push(']');
                ("any_of", val)
            }
        };
        let is_regex = self.is_regex();
        let is_complete_regex = self.is_complete_regex();

        let regex = if is_regex || is_complete_regex {
            format!("\"{}\"", self.get_regex().to_string())
        } else {
            "null".to_string()
        };
        format!(
            r#"Rule({hostname}, {{method: "{method}", pattern: {pattern} }}, {mask}, {regex}, {is_regex}, {is_complete_regex}, {is_csp}, {is_redirect}, {is_important}, {is_hostname_anchor}, {is_left_anchor}, {is_right_anchor}, {for_http}, {for_https})"#,
            mask = self.mask.bits(),
            is_csp = self.is_csp(),
            is_redirect = self.is_redirect(),
            is_important = self.is_important(),
            is_hostname_anchor = self.is_hostname_anchor(),
            is_left_anchor = self.is_left_anchor(),
            is_right_anchor = self.is_right_anchor(),
            for_http = self.for_http(),
            for_https = self.for_https(),
        )
    }
}

fn main() -> Result<(), anyhow::Error> {
    let mut settings = Settings::default();
    for path in configs() {
        if !path.exists() {
            continue;
        }
        let mut config = String::new();
        File::open(&path)?.read_to_string(&mut config)?;
        settings = toml::from_str(&config)?;
        break;
    }

    let settings = settings;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    // let parse_options = ParseOptions::default();

    let mut template =
        std::fs::read_to_string("proxy.pac.template")?.replacen("__PROXIES__", &settings.proxies, 1);

    let gfwlist_options = settings.gfwlist.unwrap_or_default();
    if gfwlist_options.enabled {
        let rules = rt.block_on(gfwlist_rules(&gfwlist_options))?;
        let (direct, over_proxy): (Vec<NetworkFilter>, Vec<NetworkFilter>) =
            rules.into_iter().partition(|rule| rule.is_exception());
        let mut gfw_direct = String::new();
        let mut gfw_proxy = String::new();
        direct.iter().for_each(|rule| {
            gfw_direct.push_str(&rule.to_javascript());
            gfw_direct.push_str(",\n");
        });
        over_proxy.iter().for_each(|rule| {
            gfw_proxy.push_str(&rule.to_javascript());
            gfw_proxy.push_str(",\n");
        });
        template = template
            .replacen("__GFW_DIRECT__", &gfw_direct, 1)
            .replacen("__GFW_PROXY__", &gfw_proxy, 1);
    }

    template = template
        .replacen("__USER_DIRECT__", "", 1)
        .replacen("__USER_PROXY__", "", 1);

    std::fs::write("proxy.pac", &template)?;

    Ok(())
}

async fn gfwlist_rules(gfwlist_options: &GFWlist) -> anyhow::Result<Vec<NetworkFilter>> {
    let mut c = request::ClientBuilder::new()
        .tcp_nodelay(true)
        .deflate(true)
        .user_agent("curl/7.87.0");
    if let Some(ref proxy) = gfwlist_options.proxy {
        println!("{}", proxy);
        let proxy = request::Proxy::all(proxy)?;
        c = c.proxy(proxy);
    }
    let c = c.build()?;

    let url: &str = if let Some(ref url) = gfwlist_options.url {
        url
    } else {
        "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
    };

    let resp = c.get(url).send().await?;
    dbg!(resp.version());
    dbg!(resp.headers().get("Content-Type"));
    dbg!(resp.content_length());
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
