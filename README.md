# CrowdSec Netfilter Blocker

This repository contains a netfilter-blocker, written in golang, that will bans IP address tagged as malevolent in the SQLite database.

# Installation

Download the [latest release](https://github.com/crowdsecurity/cs-netfilter-blocker/releases).

```bash
tar xzvf cs-netfilter-blocker.tgz
cd cs-netfilter-blocker/
sudo ./install.sh
```

# Documentation

Please find the documentation [here](https://docs.crowdsec.net/blockers/netfilter/installation/).

# How it works

When the `netfilter-blocker` service starts, it :
 - Adds a `crowdsec-blacklists` ipset
 - Inserts an `INPUT` rule for match-set `crowdsec-blacklists` with target `DROP`
 
The `netfilter-blocker` daemon will periodically pull the local database content and insert/update bans into the created `ipset`.

:warning: the `dbpath` in the [blocker's configuration file](https://github.com/crowdsecurity/cs-netfilter-blocker/blob/master/config/netfilter-blocker.yaml#L2) must be consistent with the one used by crowdwatch.

:information_source: IPv4 and IPv6 are supported.

# Troubleshooting

 - Logs are in `/var/log/netfilter-blocker.log`
 - You can view/interact directly in the ban list either with `cwcli` or direct at ipset level
 - Service can be started/stopped with `systemctl start/stop netfilter-blocker`

