package main

import (
	"fmt"
	"io/ioutil"
	"time"

	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

type blockerConfig struct {
	Mode                string `yaml:"mode"`   //ipset,iptables,tc
	Dbpath              string `yaml:"dbpath"` ///var/run/crowdsec/crowdsec-agent.db
	PidDir              string `yaml:"piddir"`
	updateFrequency     time.Duration
	UpdateFrequencyYAML string    `yaml:"update_frequency"`
	Daemon              bool      `yaml:"daemonize"`
	LogMode             string    `yaml:"log_mode"`
	LogDir              string    `yaml:"log_dir"`
	LogLevel            log.Level `yaml:"log_level"`

	DBConfig map[string]string `yaml:"db_config"`
}

func NewConfig(configPath string) (*blockerConfig, error) {
	config := &blockerConfig{}

	configBuff, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s : %v", configPath, err)
	}

	err = yaml.UnmarshalStrict(configBuff, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s : %v", configPath, err)
	}

	config.updateFrequency, err = time.ParseDuration(config.UpdateFrequencyYAML)
	if err != nil {
		return nil, fmt.Errorf("invalid update frequency %s : %s", config.UpdateFrequencyYAML, err)
	}
	if config.Dbpath == "" || config.Mode == "" || config.PidDir == "" || config.LogMode == "" {
		return nil, fmt.Errorf("invalid configuration in %s", configPath)
	}

	return config, nil
}
