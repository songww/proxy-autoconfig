# proxy-autoconfig
Proxy auto config generation tool with gfwlist.

# Install
# install to ~/.cargo/bin
$ cargo install --git https://github.com/songww/proxy-autoconfig
# create config dir
$ mkdir ~/.config/proxy-autoconfig
# copy config files
$ cp config.toml proxy.pac.template user-rules.txt ~/.config/proxy-autoconfig
# start by systemd
$ cp proxy-autoconfig.service ~/.config/systemd/user/
$ systemctl --user daemon-reload
$ systemctl --user enable proxy-autoconfig

# Config
In the system network settings, set the proxy type to auto and the url to `http://127.0.0.1:1089`

# Custom Rules
Adblock Plus syntax (e.g. EasyList, EasyPrivacy) filter parsing and matching.

Open `~/.config/proxy-autoconfig/user-rules.txt` with your favorite editor.
Put your rules here and save.
Run `proxy-autoconfigue build`.
Resetting the system proxy to take effect.
