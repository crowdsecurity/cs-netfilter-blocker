package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/sqlite"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

type CustomScript struct {
	CustomPath string
	//
}

func serializeBanApplication(ba types.BanApplication) (string, error) {
	serbyte, err := json.Marshal(ba)
	if err != nil {
		return "", fmt.Errorf("serialize error : %s", err)
	}
	return string(serbyte), nil
}

var CustomScriptCtx = &CustomScript{}

func newCustomScript(config *blockerConfig) (interface{}, error) {
	//var err error
	ret := &CustomScript{}
	ret.CustomPath = config.CustomPath
	if ret.CustomPath == "" {
		return nil, fmt.Errorf("'custom_path' can't be empty in custom mode")
	}
	log.Printf("Create context for custom action on [%s]", ret.CustomPath)
	// /*Create our set*/

	// log.Debugf("ipset ban [%s] for %d seconds (until: %s)", ban.IpText, banDuration, ban.Until)
	// cmd := exec.Command(ctx.ipsetBin, "-exist", "add", ctx.SetName, ban.IpText, "timeout", fmt.Sprintf("%d", banDuration))
	// log.Debugf("ipset add : %s", cmd.String())
	// if out, err := cmd.CombinedOutput(); err != nil {
	// 	log.Infof("Error while inserting in set (%s): %v --> %s", cmd.String(), err, string(out))
	// }

	return ret, nil
}

func (ipt *CustomScript) Init() error {
	//var err error
	log.Printf("custom action for [%s] init", ipt.CustomPath)
	return nil
}

func (ipt *CustomScript) AddBan(ban types.BanApplication) error {
	banDuration := fmt.Sprintf("%d", int(ban.Until.Sub(time.Now()).Seconds()))
	log.Printf("custom [%s] : add ban on %s for %s sec (%s)", ipt.CustomPath, ban.IpText, banDuration, ban.Reason)

	str, err := serializeBanApplication(ban)
	if err != nil {
		log.Warningf("serialize: %s", err)
	}
	cmd := exec.Command(ipt.CustomPath, "add", ban.IpText, banDuration, ban.Reason, str)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error in 'add' command (%s): %v --> %s", cmd.String(), err, string(out))
	}
	return nil
}

func (ipt *CustomScript) ShutDown() error {
	log.Printf("custom action called to shutdown")
	return nil
}

func (ipt *CustomScript) DeleteBan(ban types.BanApplication) error {
	log.Printf("custom [%s] : del ban on %s", ipt.CustomPath, ban.IpText)
	banDuration := fmt.Sprintf("%d", int(ban.Until.Sub(time.Now()).Seconds()))

	str, err := serializeBanApplication(ban)
	if err != nil {
		log.Warningf("serialize: %s", err)
	}
	cmd := exec.Command(ipt.CustomPath, "del", ban.IpText, banDuration, ban.Reason, str)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error in 'del' command (%s): %v --> %s", cmd.String(), err, string(out))
	}
	return nil
}

func (ipt *CustomScript) Run(dbCTX *sqlite.Context, frequency time.Duration) error {

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
		if err != nil {
			return err
		}
		lastTS = time.Now()

		fmt.Printf("Adding ban")
		for idx, ba := range bansToAdd {
			log.Debugf("ban %d/%d", idx, len(bansToAdd))
			if err := ipt.AddBan(ba); err != nil {
				return err
			}
		}
	}
}
