package main

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type ControllerConfig struct {
	Agents      map[string]*agentConfig `yaml:"agents"`
	Webhook     string                  `yaml:"webhook"`
	ServerNames []string                `yaml:"serverNames"`
}

type agentConfig struct {
	Identity string `yaml:"identity"`
}

func LoadConfig() (*ControllerConfig, error) {
	buf, err := ioutil.ReadFile(*configFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to load config file: %v", err)
	}

	config := &ControllerConfig{}
	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return nil, fmt.Errorf("Unable to read config file: %v", err)
	}
	return config, nil
}
