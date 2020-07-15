package main

import (
	"flag"
	"os"
	"syscall"

	"github.com/sevlyar/go-daemon"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"gopkg.in/natefinch/lumberjack.v2"
)

type mode interface {
	Startup() error
	AddBan(types.BanApplication) error
	UpdateBan(types.BanApplication) error
	DeleteBan(types.BanApplication) error
	Shutdown() error
}

var config *blockerConfig

func termHandler(sig os.Signal) error {
	backend, err := newBackend(config.Mode)
	if err != nil {
		log.Fatalf("backend shutdown init failed: %s", err)
	}
	if err := backend.ShutDown(); err != nil {
		log.Fatalf("Cleanup/shutdown failed : %v", err)
	}
	return daemon.ErrStop
}

func main() {
	var err error

	configPath := flag.String("c", "", "path to netfilter-connector.yaml")
	flag.Parse()

	if configPath == nil || *configPath == "" {
		log.Fatalf("config file required")
	}

	config, err := NewConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	// Configure logging
	if err = types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel); err != nil {
		log.Fatal(err.Error())
	}

	//daemon.SetSigHandler(ReloadHandler, syscall.SIGHUP)

	dctx := &daemon.Context{
		PidFileName: config.PidDir + "/netfilter-blocker.pid",
		PidFilePerm: 0644,
		WorkDir:     "./",
		Umask:       027,
	}

	if config.Daemon {
		daemon.SetSigHandler(termHandler, syscall.SIGTERM)

		d, err := dctx.Reborn()
		if err != nil {
			log.Fatal("Unable to run: ", err)
		}
		if d != nil {
			return
		}
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

	dbCTX, err := database.NewDatabase(config.DBConfig)
	if err != nil {
		log.Fatalf("unable to init sqlite : %v", err)
	}

	backend, err := newBackend(config.Mode)
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = backend.Init()
	if err != nil {
		log.Fatalf(err.Error())
	}

	if config.Daemon == true {

		go backend.Run(dbCTX, config.updateFrequency)

		defer dctx.Release()

		/*if we are into daemon mode, only process signals*/
		err = daemon.ServeSignals()
		if err != nil {
			log.Fatalf("error running daemon: %s", err.Error())
		}
	} else {
		backend.Run(dbCTX, config.updateFrequency)
	}

}
