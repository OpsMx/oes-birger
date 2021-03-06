package kubeconfig

import (
	"fmt"
	"io"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// KubeConfig defines a kubectl config file contents.  The structure maps the file format,
// so some of this is a little klunky.
type KubeConfig struct {
	APIVersion     string    `yaml:"apiVersion" json:"apiVersion"`
	Kind           string    `yaml:"kind" json:"kind"`
	CurrentContext string    `yaml:"current-context,omitempty" json:"current-context,omitempty"`
	Clusters       []Cluster `yaml:"clusters" json:"clusters"`
	Contexts       []Context `yaml:"contexts" json:"contexts"`
	Users          []User    `yaml:"users" json:"users"`
}

// Context associates a name with a ContextDetails.
type Context struct {
	Name    string         `yaml:"name" json:"name"`
	Context ContextDetails `yaml:"context" json:"context"`
}

// ContextDetails holds the names of the referenced cluster and user.
type ContextDetails struct {
	Cluster string `yaml:"cluster" json:"cluster"`
	User    string `yaml:"user" json:"user"`
}

// Cluster associates a name with a ClusterDetails.
type Cluster struct {
	Name    string         `yaml:"name" json:"name"`
	Cluster ClusterDetails `yaml:"cluster" json:"cluster"`
}

// ClusterDetails holds the certificate authority data, server name to connect to, and if we should
// skip TLS server identity verification.
type ClusterDetails struct {
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty" json:"insecure-skip-tls-verify,omitempty"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty" json:"certificate-authority-data,omitempty"`
	Server                   string `yaml:"server" json:"server"`
}

// User associates a name with a UserDetails.
type User struct {
	Name string      `yaml:"name" json:"name"`
	User UserDetails `yaml:"user" json:"user"`
}

// UserDetails holds the user's certificate information.
type UserDetails struct {
	ClientCertificateData string `yaml:"client-certificate-data" json:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data" json:"client-key-data"`
}

// ReadKubeConfig will read in the YAML config located in $HOME/.kube/config
func ReadKubeConfig(contents io.Reader) (*KubeConfig, error) {
	buf, err := ioutil.ReadAll(contents)
	if err != nil {
		return nil, err
	}

	c := &KubeConfig{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("Unable to unmarshal from YAML: %v", err)
	}

	if c.APIVersion != "v1" {
		return nil, fmt.Errorf("apiVersion '%s' is not 'v1'", c.APIVersion)
	}

	if c.Kind != "Config" {
		return nil, fmt.Errorf("kind '%s' is not 'Config'", c.Kind)
	}

	return c, nil
}

func (kc *KubeConfig) findContext(name string) (*ContextDetails, error) {
	for _, b := range kc.Contexts {
		if b.Name == name {
			return &b.Context, nil
		}
	}
	return nil, fmt.Errorf("Unable to find context named %s", name)
}

func (kc *KubeConfig) findUser(name string) (*User, error) {
	for _, b := range kc.Users {
		if b.Name == name {
			return &b, nil
		}
	}
	return nil, fmt.Errorf("Unable to find user named %s", name)
}

func (kc *KubeConfig) findCluster(name string) (*Cluster, error) {
	for _, b := range kc.Clusters {
		if b.Name == name {
			return &b, nil
		}
	}
	return nil, fmt.Errorf("Unable to find cluster named %s", name)
}

// GetContextNames returns a list of all context names.
func (kc *KubeConfig) GetContextNames() []string {
	names := make([]string, 0)
	for _, b := range kc.Contexts {
		names = append(names, b.Name)
	}
	return names
}

// FindContext finds a context by name, and returns the associated UserDetails and ClusterDetails.  An error
// is returned if any of this path is missing.
func (kc *KubeConfig) FindContext(name string) (*User, *Cluster, error) {
	context, err := kc.findContext(name)
	if err != nil {
		return nil, nil, err
	}
	if len(context.Cluster) == 0 {
		return nil, nil, fmt.Errorf("Context %s has no cluster name defined", name)
	}
	if len(context.User) == 0 {
		return nil, nil, fmt.Errorf("Context %s has no user name defined", name)
	}

	user, err := kc.findUser(context.User)
	if err != nil {
		return nil, nil, err
	}

	cluster, err := kc.findCluster(context.Cluster)
	if err != nil {
		return nil, nil, err
	}

	return user, cluster, nil
}
