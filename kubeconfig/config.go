package kubeconfig

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

// KubeConfig defines a kubectl config file contents.
type KubeConfig struct {
	APIVersion     string `yaml:"apiVersion" json:"apiVersion"`
	Kind           string `yaml:"kind" json:"kind"`
	CurrentContext string `yaml:"current-context,omitempty" json:"current-context,omitempty"`
	Clusters       []struct {
		Name    string `yaml:"name" json:"name"`
		Cluster struct {
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty" json:"insecure-skip-tls-verify,omitempty"`
			CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty" json:"certificate-authority-data,omitempty"`
			Server                   string `yaml:"server" json:"server"`
		} `yaml:"cluster" json:"cluster"`
	} `yaml:"clusters" json:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name" json:"name"`
		Context struct {
			Cluster string `yaml:"cluster" json:"cluster"`
			User    string `yaml:"user" json:"user"`
		} `yaml:"context" json:"context"`
	} `yaml:"contexts" json:"contexts"`
	Users []struct {
		Name string `yaml:"name" json:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data" json:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data" json:"client-key-data"`
		} `yaml:"user" json:"user"`
	} `yaml:"users" json:"users"`
}

// ReadKubeConfig will read in the YAML config located in $HOME/.kube/config
func ReadKubeConfig() (*KubeConfig, error) {
	filename := os.Getenv("HOME") + "/.kube/config"

	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &KubeConfig{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %v", filename, err)
	}

	if c.APIVersion != "v1" || c.Kind != "Config" {
		return nil, fmt.Errorf("APIVersion %s, kind %s is not 'v1' and 'Config'", c.APIVersion, c.Kind)
	}

	return c, nil
}
