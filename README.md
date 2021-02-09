:warning: cs-netfilter-blocker is deprecated and you should move to https://github.com/crowdsecurity/cs-firewall-bouncer for versions >= 1.X

<p align="center">
<img src="https://github.com/crowdsecurity/cs-netfilter-blocker/raw/master/docs/assets/crowdsec_linux_logo.png" alt="CrowdSec" title="CrowdSec" width="280" height="300" />
</p>
<p align="center">
<img src="https://img.shields.io/badge/build-pass-green">
<img src="https://img.shields.io/badge/tests-pass-green">
</p>
<p align="center">
&#x1F4DA; <a href="https://docs.crowdsec.net/blockers/netfilter/installation/">Documentation</a>
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>

# CrowdSec Netfilter Blocker

A netfilter blocker relying on `iptables` and `ipset`.

# How does it work ?

The netfilter-blocker will monitor bans from SQLite or MySQL database (fed by crowdsec), and update a set of banned IPs / ranges.

# Installation

netfilter-blocker requires `ipset` and `iptables`, and defaults to SQLite backend type.

## Install script

Download the [latest release](https://github.com/crowdsecurity/cs-netfilter-blocker/releases).

```bash
tar xzvf cs-netfilter-blocker.tgz
cd cs-netfilter-blocker/
sudo ./install.sh
systemctl status netfilter-blocker
```

## From source

:warning: requires  go >= 1.13

```bash
make release
tar xvzf cs-netfilter-blocker.tgz
cd cs-netfilter-blocker-vX.X.X
sudo ./install.sh
```


# Configuration

Configuration can be found in `/etc/crowdsec/netfilter-blocker/netfilter-blocker.yaml`.
The default is to use SQLite as a backend :

```yaml
# only supported mode is iptables
mode: iptables
piddir: /var/run/
# how often we check for updates
update_frequency: 10s
# go to background
daemonize: true
# stdout or file
log_mode: file
log_dir: /var/log/
log_level: info
db_config:
  ## DB type supported (mysql, sqlite)
  ## By default it using sqlite
  type: sqlite

  ## mysql options
  # db_host: localhost
  # db_username: crowdsec
  # db_password: crowdsec
  # db_name: crowdsec

  ## sqlite options
  db_path: /var/lib/crowdsec/data/crowdsec.db

  ## Other options
  flush: true
  # debug: true

```

<details>
  <summary>MySQL configuration</summary>

```yaml
# only supported mode is iptables
mode: iptables
piddir: /var/run/
# how often we check for updates
update_frequency: 10s
# go to background
daemonize: true
# stdout or file
log_mode: file
log_dir: /var/log/
log_level: info
db_config:
  ## DB type supported (mysql, sqlite)
  ## By default it using sqlite
  type: mysql

  ## mysql options
  db_host: localhost
  db_username: crowdsec
  db_password: crowdsec
  db_name: crowdsec

  ## sqlite options
  #db_path: /var/lib/crowdsec/data/crowdsec.db

  ## Other options
  flush: true
  # debug: true

```
</details>

# How it works

When the `netfilter-blocker` service starts, it :
 - Create a `crowdsec-blacklists` ipset list for IPv4 address
 - Create a `crowdsec6-blacklists` ipset list for IPv6 address
 - Inserts an `INPUT` rule for match-set both `crowdsec-blacklists` and `crowdsec6-blacklists` with target `DROP`
 
The `netfilter-blocker` daemon will periodically pull the local database content and insert/update bans into the created `ipset`.

:warning: the `dbpath` in the [blocker's configuration file](https://github.com/crowdsecurity/cs-netfilter-blocker/blob/master/config/netfilter-blocker.yaml#L2) must be consistent with the one used by crowdwatch.

:information_source: IPv4 and IPv6 are supported.

# Troubleshooting

 - Logs are in `/var/log/netfilter-blocker.log`
 - You can view/interact directly in the ban list either with `cscli` or direct at ipset level
 - Service can be started/stopped with `systemctl start/stop netfilter-blocker`

