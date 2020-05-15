package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/sqlite"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/sevlyar/go-daemon"
	"gopkg.in/yaml.v2"
)

type NetfilterConfig struct {
	Mode             string `yaml:"mode"`   //ipset,iptables,tc
	Dbpath           string `yaml:"dbpath"` ///var/run/crowdsec/crowdsec-agent.db
	PidDir           string `yaml:"piddir"`
	update_frequency time.Duration
	UpdateFrequency  string `yaml:"update_frequency"`
	Daemon           bool   `yaml:"daemonize"`
	LogMode          string `yaml:"log_mode"`
	LogDir           string `yaml:"log_dir"`
}

type mode interface {
	Startup() error
	AddBan(types.BanApplication) error
	UpdateBan(types.BanApplication) error
	DeleteBan(types.BanApplication) error
	Shutdown() error
}

type ipset struct {
	Name             string
	ipsetCMD         string
	iptablesCMD      string
	SetName          string   //crowdsec-netfilter
	StartupCmds      []string //-I INPUT -m set --match-set myset src -j DROP
	ShutdownCmds     []string //-D INPUT -m set --match-set myset src -j DROP
	CheckIptableCmds []string
}

var (
	modeCtx  ipset
	modeCtx6 ipset
)

func run(dbCTX *sqlite.Context, modeCtx *ipset, modeCtx6 *ipset, frequency time.Duration) {

	var bas []types.BanApplication

	lastTS := time.Now()
	/*start by getting valid bans in db ^^ */
	log.Infof("Fetching existing bans from DB")
	//select the news bans
	banRecords := dbCTX.Db.
		Order("updated_at desc").
		/*Get non expired (until) bans*/
		Where(`strftime("%s", until) >= strftime("%s", "now")`).
		/*Only get one ban per unique ip_text*/
		Group("ip_text").
		Find(&bas)
	if banRecords.Error != nil {
		log.Fatalf("Failed when selection bans : %v", banRecords.Error)
	}
	log.Infof("%d pending bans to add", banRecords.RowsAffected)
	for idx, ba := range bas {
		log.Debugf("ban %d/%d", idx, len(bas))

		//we now have to know if ba is for an ipv4 or ipv6
		//the obvious way would be to get the len of net.ParseIp(ba) but this is 16 internally even for ipv4.
		//so we steal the ugly hack from https://github.com/asaskevich/govalidator/blob/3b2665001c4c24e3b076d1ca8c428049ecbb925b/validator.go#L501
		done := false
		if strings.Contains(ba.IpText, ":") {
			if err := modeCtx6.AddBan(ba); err != nil {
				log.Fatalf("Failed inserting ban")
			}
			done = true
		}
		if strings.Contains(ba.IpText, ".") {
			if err := modeCtx.AddBan(ba); err != nil {
				log.Fatalf("Failed inserting ban")
			}
			done = true
		}
		if !done {
			log.Fatalf("Failed inserting ban: ip %s was not recognised", ba.IpText)
		}
	}
	/*go for loop*/
	for {
		// check if ipset set and iptables rules are still present. if not creat them
		if err := modeCtx.Startup(); err != nil {
			log.Fatalf(err.Error())
		}
		if err := modeCtx6.Startup(); err != nil {
			log.Fatalf(err.Error())
		}
		time.Sleep(frequency)
		//select deleted bans
		//ctx.Db.LogMode(true)

		deletedRecords := dbCTX.Db.
			/*ignore the soft delete*/
			Unscoped().
			Order("updated_at desc").
			/*ban that were deleted since lastTS or bans that expired since lastTS*/
			Where(`strftime("%s", deleted_at) >= strftime("%s", ?) OR 
				   (strftime("%s", until) >= strftime("%s", ?) AND strftime("%s", until) <= strftime("%s", "now"))`,
				lastTS.Add(1*time.Second), lastTS.Add(1*time.Second)).
			/*Only get one ban per unique ip_text*/
			Group("ip_text").
			Find(&bas) /*.Count(&count)*/

		if deletedRecords.Error != nil {
			log.Fatalf("Failed when selection deleted bans : %v", deletedRecords.Error)
		}
		if deletedRecords.RowsAffected > 0 {
			log.Infof("%d bans to flush since %s", deletedRecords.RowsAffected, lastTS)
		}
		for idx, ba := range bas {
			log.Debugf("delete ban %d/%d", idx, len(bas))

			done := false
			if strings.Contains(ba.IpText, ":") {
				if err := modeCtx6.DeleteBan(ba); err != nil {
					log.Fatalf("Failed deleting ban")
				}
				done = true
			}
			if strings.Contains(ba.IpText, ".") {
				if err := modeCtx.DeleteBan(ba); err != nil {
					log.Fatalf("Failed deleting ban")
				}
				done = true
			}
			if !done {
				log.Fatalf("Failed inserting ban: ip %s was not recognised", ba.IpText)
			}
		}

		banRecords := dbCTX.Db.
			Order("updated_at desc").
			/*Get non expired (until) bans*/
			Where(`strftime("%s", until) >= strftime("%s", "now")`).
			/*That were added since last tick*/
			Where(`strftime("%s", updated_at) >= strftime("%s", ?)`, lastTS).
			/*Only get one ban per unique ip_text*/
			Group("ip_text").
			Find(&bas) /*.Count(&count)*/
		if banRecords.Error != nil {
			log.Fatalf("Failed when selection bans : %v", banRecords.Error)
		}
		if banRecords.RowsAffected > 0 {
			log.Infof("%d bans to add", banRecords.RowsAffected)
		}
		for idx, ba := range bas {
			log.Debugf("ban %d/%d", idx, len(bas))
			done := false
			if strings.Contains(ba.IpText, ":") {
				if err := modeCtx6.AddBan(ba); err != nil {
					log.Fatalf("Failed inserting ban")
				}
				done = true
			}
			if strings.Contains(ba.IpText, ".") {
				if err := modeCtx.AddBan(ba); err != nil {
					log.Fatalf("Failed inserting ban")
				}
				done = true
			}
			if !done {
				log.Fatalf("Failed inserting ban: ip %s was not recognised", ba.IpText)
			}
		}
		lastTS = time.Now()
	}
}

func termHandler(sig os.Signal) error {
	if err := modeCtx.shutDown(); err != nil {
		log.Fatalf("Cleanup/shutdown failed : %v", err)
	}
	return daemon.ErrStop
}

func main() {
	var err error

	modeCtx = ipset{
		Name:             "ipset",
		SetName:          "crowdsec-blacklists",
		StartupCmds:      []string{"-I", "INPUT", "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", "DROP"},
		ShutdownCmds:     []string{"-D", "INPUT", "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", "DROP"},
		CheckIptableCmds: []string{"-C", "INPUT", "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", "DROP"},
	}

	modeCtx6 = ipset{
		Name:             "ipset",
		SetName:          "crowdsec6-blacklists",
		StartupCmds:      []string{"-I", "INPUT", "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"},
		ShutdownCmds:     []string{"-D", "INPUT", "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"},
		CheckIptableCmds: []string{"-C", "INPUT", "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"},
	}

	config := NetfilterConfig{}

	configPath := flag.String("c", "", "path to netfilter-connector.yaml")
	flag.Parse()

	if configPath == nil || *configPath == "" {
		log.Fatalf("config file required")
	}
	configBuff, err := ioutil.ReadFile(*configPath)

	if err != nil {
		log.Fatalf("failed to read %s : %v", *configPath, err)
	}

	err = yaml.UnmarshalStrict(configBuff, &config)
	if err != nil {
		log.Fatalf("failed to unmarshal %s : %v", *configPath, err)
	}

	config.update_frequency, err = time.ParseDuration(config.UpdateFrequency)
	if err != nil {
		log.Fatalf("invalid update frequency %s : %s", config.UpdateFrequency, err)
	}
	if config.Dbpath == "" || config.Mode == "" || config.PidDir == "" || config.LogMode == "" {
		log.Fatalf("invalid configuration in %s", *configPath)
	}

	/*Configure logging*/
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		log.SetOutput(&lumberjack.Logger{
			Filename:   config.LogDir + "/netfilter-blocker.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		})
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if config.LogMode != "stdout" {
		log.Fatalf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}

	dbCTX, err := sqlite.NewSQLite(map[string]string{"db_path": config.Dbpath})
	if err != nil {
		log.Fatalf("unable to init sqlite : %v", err)
	}
	//cleanup previous stuff in case of crash or what

	modeCtx.ipsetCMD, err = exec.LookPath("ipset")

	if err != nil {
		log.Fatalf("Unable to find ipset.")
	}
	modeCtx.iptablesCMD, err = exec.LookPath("iptables")
	if err != nil {
		log.Fatalf("Unable to find iptables.")
	}
	modeCtx6.ipsetCMD, err = exec.LookPath("ipset")
	if err != nil {
		log.Fatalf("Unable to find ipset.")
	}
	modeCtx6.iptablesCMD, err = exec.LookPath("ip6tables")

	if err != nil {
		log.Fatalf("Unable to find iptables.")
	}

	if err := modeCtx.shutDown(); err != nil {
		log.Fatalf("Startup failed")
	}

	if err := modeCtx.Startup(); err != nil {
		log.Fatalf("Startup failed")
	}

	if err := modeCtx6.shutDown(); err != nil {
		log.Fatalf("Startup6 failed")
	}

	if err := modeCtx6.Startup(); err != nil {
		log.Fatalf("Startup6 failed")
	}

	if config.Daemon == true {

		go run(dbCTX, &modeCtx, &modeCtx6, config.update_frequency)

		daemon.SetSigHandler(termHandler, syscall.SIGTERM)
		//daemon.SetSigHandler(ReloadHandler, syscall.SIGHUP)

		dctx := &daemon.Context{
			PidFileName: config.PidDir + "/netfilter-blocker.pid",
			PidFilePerm: 0644,
			WorkDir:     "./",
			Umask:       027,
		}

		d, err := dctx.Reborn()
		if err != nil {
			log.Fatal("Unable to run: ", err)
		}
		if d != nil {
			return
		}
		defer dctx.Release()

		/*if we are into daemon mode, only process signals*/
		err = daemon.ServeSignals()
		if err != nil {
			log.Errorf("Error: %s", err.Error())
		}
	} else {
		run(dbCTX, &modeCtx, &modeCtx6, config.update_frequency)
	}

}

// Startup check if ipset set and iptables rules exist. If not create them
func (ipset *ipset) Startup() error {

	/*Create our set*/
	err := ipset.checkIpsetListExist()
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	//waiting for propagation
	time.Sleep(1 * time.Second)

	// Create iptable to rule to attach the set
	err = ipset.checkIptableRuleExist()
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	return nil
}

func (ipset *ipset) checkIptableRuleExist() error {
	cmd := exec.Command(ipset.iptablesCMD, ipset.CheckIptableCmds...)
	if _, err := cmd.CombinedOutput(); err == nil {
		return nil
	}

	cmd = exec.Command(ipset.iptablesCMD, ipset.StartupCmds...)
	log.Infof("iptables set-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Error while insert set in iptables (%s): %v --> %s", cmd.String(), err, string(out))
	}

	return nil
}

func (ipset *ipset) checkIpsetListExist() error {
	var err error
	cmd := exec.Command(ipset.ipsetCMD, "-L", ipset.SetName)
	if _, err = cmd.CombinedOutput(); err == nil {
		return nil
	}
	if ipset.SetName == "crowdsec-blacklists" {
		cmd = exec.Command(ipset.ipsetCMD, "-exist", "create", ipset.SetName, "nethash", "timeout", "300")
		log.Infof("ipset set-up : %s", cmd.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("Error while creating set : %v --> %s", err, string(out))
		}
	}

	if ipset.SetName == "crowdsec6-blacklists" {
		cmd = exec.Command(ipset.ipsetCMD, "-exist", "create", ipset.SetName, "nethash", "timeout", "300", "family", "inet6")
		log.Infof("ipset set-up : %s", cmd.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("Error while creating set : %v --> %s", err, string(out))
		}
	}
	return nil
}

func (ipset *ipset) AddBan(ban types.BanApplication) error {
	/*Create our set*/
	banDuration := int(ban.Until.Sub(time.Now()).Seconds())
	log.Infof("ipset ban [%s] for %d seconds (until: %s)", ban.IpText, banDuration, ban.Until)
	cmd := exec.Command(ipset.ipsetCMD, "-exist", "add", ipset.SetName, ban.IpText, "timeout", fmt.Sprintf("%d", banDuration))
	log.Debugf("ipset add : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while inserting in set (%s): %v --> %s", cmd.String(), err, string(out))
	}
	//ipset -exist add test 192.168.0.1 timeout 600
	return nil
}

func (*ipset) UpdateBan(ban types.BanApplication) error {
	/*
		DeleteBan(ban)
		AddBan(ban)
	*/
	return nil
}
func (ipset *ipset) DeleteBan(ban types.BanApplication) error {
	/*
		ipset -exist delete test 192.168.0.1 timeout 600
		ipset -exist add test 192.168.0.1 timeout 600
	*/
	log.Infof("ipset del ban for [%s]", ban.IpText)
	cmd := exec.Command(ipset.ipsetCMD, "-exist", "del", ipset.SetName, ban.IpText)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while deleting from set (%s): %v --> %s", cmd.String(), err, string(out))
	}
	//ipset -exist add test 192.168.0.1 timeout 600
	return nil
}
func (ipset *ipset) shutDown() error {
	/*Now run the request clean-up Cmds*/
	cmd := exec.Command(ipset.iptablesCMD, ipset.ShutdownCmds...)
	log.Infof("iptables clean-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		/*if the set doesn't exist, don't frigthen user with error messages*/
		if strings.Contains(string(out), "Set crowdsec-blacklists doesn't exist.") {
			log.Infof("ipset 'crowdsec-blacklists' doesn't exist, skip")
		} else {
			log.Infof("error while removing set entry in iptables : %v --> %s", err, string(out))
		}
	}
	/*destroy our set*/
	cmd = exec.Command(ipset.ipsetCMD, "-exist", "destroy", ipset.SetName)
	log.Infof("ipset clean-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "The set with the given name does not exist") {
			log.Infof("ipset 'crowdsec-blacklists' doesn't exist, skip")
		} else {
			log.Infof("Error while destroying set : %v --> %s", err, string(out))
		}
	}

	return nil

}
