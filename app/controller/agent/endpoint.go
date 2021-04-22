package agent

import "fmt"

type Endpoint struct {
	Name       string   `json:"name,omitempty"`
	Type       string   `json:"type,omitempty"`
	Configured bool     `json:"configured,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
}

func (e *Endpoint) String() string {
	return fmt.Sprintf("(%s, %s, %v)", e.Type, e.Name, e.Configured)
}
