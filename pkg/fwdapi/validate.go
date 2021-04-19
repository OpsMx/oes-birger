package fwdapi

import (
	"fmt"
	"log"
	"regexp"
)

// NamePresent ensures the string is not null.
func namePresent(n string) bool {
	return n != ""
}

// TypeValid ensures type is valid, that is, lowercase alpha only
func typeValid(n string) bool {
	matched, err := regexp.MatchString("^[a-z]+$", n)
	if err != nil {
		// TODO: handle this better
		log.Printf("matching service type: %v", err)
		return false
	}
	return matched
}

func (req *ServiceCredentialRequest) Validate() error {
	if !namePresent(req.AgentName) {
		return fmt.Errorf("'agentName' is invalid")
	}

	if !namePresent(req.Name) {
		return fmt.Errorf("'name' is invalid")
	}

	if !typeValid(req.Type) {
		return fmt.Errorf("'type' is invalid")
	}

	return nil
}

func (req *KubeConfigRequest) Validate() error {
	if !namePresent(req.AgentName) {
		return fmt.Errorf("'agentName' is invalid")
	}

	if !namePresent(req.Name) {
		return fmt.Errorf("'name' is invalid")
	}

	return nil
}

func (req *ManifestRequest) Validate() error {
	if !namePresent(req.AgentName) {
		return fmt.Errorf("'agentName' is invalid")
	}

	return nil
}
