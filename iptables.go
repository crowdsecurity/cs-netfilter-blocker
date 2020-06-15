package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/sqlite"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

type iptables struct {
	v4 *ipTablesContext
	v6 *ipTablesContext
}

var iptablesCtx = &iptables{}

func newIPTables(config *blockerConfig) (interface{}, error) {
	var err error
	ipv4Ctx := &ipTablesContext{
		Name:             "ipset",
		version:          "v4",
		SetName:          "crowdsec-blacklists",
		StartupCmds:      []string{"-I", "INPUT", "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", "DROP"},
		ShutdownCmds:     []string{"-D", "INPUT", "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", "DROP"},
		CheckIptableCmds: []string{"-C", "INPUT", "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", "DROP"},
	}

	ipv6Ctx := &ipTablesContext{
		Name:             "ipset",
		version:          "v6",
		SetName:          "crowdsec6-blacklists",
		StartupCmds:      []string{"-I", "INPUT", "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"},
		ShutdownCmds:     []string{"-D", "INPUT", "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"},
		CheckIptableCmds: []string{"-C", "INPUT", "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"},
	}

	ipsetBin, err := exec.LookPath("ipset")
	if err != nil {
		return nil, fmt.Errorf("unable to find ipset")
	}

	ipv4Ctx.iptablesBin, err = exec.LookPath("iptables")
	if err != nil {
		return nil, fmt.Errorf("unable to find iptables")
	}
	ipv4Ctx.ipsetBin = ipsetBin
	ipv6Ctx.ipsetBin = ipsetBin
	ipv6Ctx.iptablesBin, err = exec.LookPath("ip6tables")
	if err != nil {
		return nil, fmt.Errorf("unable to find iptables")
	}

	ret := &iptables{
		v4: ipv4Ctx,
		v6: ipv6Ctx,
	}

	return ret, nil
}

func (ipt *iptables) Init() error {
	var err error

	log.Printf("iptables for ipv4 initiated")
	err = ipt.v4.shutDown() // flush before init
	if err != nil {
		return fmt.Errorf("iptables shutdown failed: %s", err.Error())
	}

	// Create iptable to rule to attach the set
	err = ipt.v4.CheckAndCreate()
	if err != nil {
		return fmt.Errorf("iptables init failed: %s", err.Error())
	}

	log.Printf("iptables for ipv6 initiated")
	err = ipt.v6.shutDown() // flush before init
	if err != nil {
		return fmt.Errorf("iptables shutdown failed: %s", err.Error())
	}

	// Create iptable to rule to attach the set
	err = ipt.v6.CheckAndCreate()
	if err != nil {
		return fmt.Errorf("iptables init failed: %s", err.Error())
	}

	return nil
}

func (ipt *iptables) AddBan(ban types.BanApplication) error {
	done := false

	//we now have to know if ba is for an ipv4 or ipv6
	//the obvious way would be to get the len of net.ParseIp(ba) but this is 16 internally even for ipv4.
	//so we steal the ugly hack from https://github.com/asaskevich/govalidator/blob/3b2665001c4c24e3b076d1ca8c428049ecbb925b/validator.go#L501
	if strings.Contains(ban.IpText, ":") {
		if err := ipt.v6.addBan(ban); err != nil {
			return fmt.Errorf("failed inserting ban ip '%s' for iptables ipv4 rule", ban.IpText)
		}
		done = true
	}
	if strings.Contains(ban.IpText, ".") {
		if err := ipt.v4.addBan(ban); err != nil {
			return fmt.Errorf("failed inserting ban ip '%s' for iptables ipv6 rule", ban.IpText)
		}
		done = true
	}

	if !done {
		return fmt.Errorf("failed inserting ban: ip %s was not recognised", ban.IpText)
	}

	return nil
}

func (ipt *iptables) ShutDown() error {
	err := ipt.v4.shutDown()
	if err != nil {
		return fmt.Errorf("iptables for ipv4 shutdown failed: %s", err.Error())
	}
	err = ipt.v6.shutDown()
	if err != nil {
		return fmt.Errorf("iptables for ipv6 shutdown failed: %s", err.Error())
	}
	return nil
}

func (ipt *iptables) DeleteBan(ban types.BanApplication) error {
	done := false
	if strings.Contains(ban.IpText, ":") {
		if err := ipt.v6.deleteBan(ban); err != nil {
			return fmt.Errorf("failed deleting ban")
		}
		done = true
	}
	if strings.Contains(ban.IpText, ".") {
		if err := ipt.v4.deleteBan(ban); err != nil {
			return fmt.Errorf("failed deleting ban")
		}
		done = true
	}
	if !done {
		return fmt.Errorf("failed inserting ban: ip %s was not recognised", ban.IpText)
	}
	return nil
}

func (ipt *iptables) Run(dbCTX *sqlite.Context, frequency time.Duration) error {

	lastTS := time.Now()
	/*start by getting valid bans in db ^^ */
	log.Infof("fetching existing bans from DB")
	bansToAdd, err := getNewBan(dbCTX, time.Time{})
	if err != nil {
		return err
	}
	log.Infof("found %d bans in DB", len(bansToAdd))
	for idx, ba := range bansToAdd {
		log.Debugf("ban %d/%d", idx, len(bansToAdd))
		if err := ipt.AddBan(ba); err != nil {
			return err
		}

	}
	/*go for loop*/
	for {
		// check if ipset set and iptables rules are still present. if not creat them
		if err := ipt.v4.CheckAndCreate(); err != nil {
			return err
		}
		if err := ipt.v6.CheckAndCreate(); err != nil {
			return err
		}
		time.Sleep(frequency)

		bas, err := getDeletedBan(dbCTX, lastTS)
		if err != nil {
			return err
		}
		if len(bas) > 0 {
			log.Infof("%d bans to flush since %s", len(bas), lastTS)
		}
		for idx, ba := range bas {
			log.Debugf("delete ban %d/%d", idx, len(bas))
			if err := ipt.DeleteBan(ba); err != nil {
				return err
			}
		}

		bansToAdd, err := getNewBan(dbCTX, lastTS)
		lastTS = time.Now()
		if err != nil {
			return err
		}
		fmt.Printf("Adding ban")
		for idx, ba := range bansToAdd {
			log.Debugf("ban %d/%d", idx, len(bansToAdd))
			if err := ipt.AddBan(ba); err != nil {
				return err
			}
		}
	}
}
