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

type ipTablesContext struct {
	Name             string
	version          string
	ipsetBin         string
	iptablesBin      string
	SetName          string   //crowdsec-netfilter
	StartupCmds      []string //-I INPUT -m set --match-set myset src -j DROP
	ShutdownCmds     []string //-D INPUT -m set --match-set myset src -j DROP
	CheckIptableCmds []string
}

type iptables struct {
	v4 *ipTablesContext
	v6 *ipTablesContext
}

var iptablesCtx = &iptables{}

func NewIPTables() (interface{}, error) {
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
	bansToAdd, err := getNewBan(dbCTX)
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

		bansToAdd, err := getNewBan(dbCTX)
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
		lastTS = time.Now()
	}
}

func (ctx *ipTablesContext) CheckAndCreate() error {
	var err error

	/* check if the set already exist */
	cmd := exec.Command(ctx.ipsetBin, "-L", ctx.SetName)
	if _, err = cmd.CombinedOutput(); err != nil { // if doesn't exist, create it
		if ctx.version == "v6" {
			cmd = exec.Command(ctx.ipsetBin, "-exist", "create", ctx.SetName, "nethash", "timeout", "300", "family", "inet6")
		} else {
			cmd = exec.Command(ctx.ipsetBin, "-exist", "create", ctx.SetName, "nethash", "timeout", "300")
		}
		log.Infof("ipset set-up : %s", cmd.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("Error while creating set : %v --> %s", err, string(out))
		}
	}

	//waiting for propagation
	time.Sleep(1 * time.Second)

	// checking if iptables rules exist
	cmd = exec.Command(ctx.iptablesBin, ctx.CheckIptableCmds...)
	if _, err := cmd.CombinedOutput(); err != nil { // if doesn't exist, create it
		cmd = exec.Command(ctx.iptablesBin, ctx.StartupCmds...)
		log.Infof("iptables set-up : %s", cmd.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("Error while insert set in iptables (%s): %v --> %s", cmd.String(), err, string(out))
		}
	}

	return nil
}

func (ipset *ipTablesContext) addBan(ban types.BanApplication) error {
	/*Create our set*/
	banDuration := int(ban.Until.Sub(time.Now()).Seconds())
	log.Debugf("ipset ban [%s] for %d seconds (until: %s)", ban.IpText, banDuration, ban.Until)
	cmd := exec.Command(ipset.ipsetBin, "-exist", "add", ipset.SetName, ban.IpText, "timeout", fmt.Sprintf("%d", banDuration))
	log.Debugf("ipset add : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while inserting in set (%s): %v --> %s", cmd.String(), err, string(out))
	}
	//ipset -exist add test 192.168.0.1 timeout 600
	return nil
}

func (ctx *ipTablesContext) shutDown() error {
	/*clean iptables rules*/
	cmd := exec.Command(ctx.iptablesBin, ctx.ShutdownCmds...)
	log.Infof("iptables clean-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		/*if the set doesn't exist, don't frigthen user with error messages*/
		if strings.Contains(string(out), "Set crowdsec-blacklists doesn't exist.") {
			log.Infof("ipset 'crowdsec-blacklists' doesn't exist, skip")
		} else {
			log.Errorf("error while removing set entry in iptables : %v --> %s", err, string(out))
		}
	}
	/*clean ipset set*/
	cmd = exec.Command(ctx.ipsetBin, "-exist", "destroy", ctx.SetName)
	log.Infof("ipset clean-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "The set with the given name does not exist") {
			log.Infof("ipset 'crowdsec-blacklists' doesn't exist, skip")
		} else {
			log.Errorf("Error while destroying set : %v --> %s", err, string(out))
		}
	}

	return nil
}

func (ipset *ipTablesContext) deleteBan(ban types.BanApplication) error {
	/*
		ipset -exist delete test 192.168.0.1 timeout 600
		ipset -exist add test 192.168.0.1 timeout 600
	*/
	log.Infof("ipset del ban for [%s]", ban.IpText)
	cmd := exec.Command(ipset.ipsetBin, "-exist", "del", ipset.SetName, ban.IpText)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while deleting from set (%s): %v --> %s", cmd.String(), err, string(out))
	}
	//ipset -exist add test 192.168.0.1 timeout 600
	return nil
}
