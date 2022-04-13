package fwdapi

/*
 * Copyright 2021 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"fmt"
	"regexp"

	"go.uber.org/zap"
)

// NamePresent ensures the string is not null.
func namePresent(n string) bool {
	return n != ""
}

// TypeValid ensures type is valid, that is, lowercase alphanumeric only
func typeValid(n string) bool {
	matched, err := regexp.MatchString("^[a-z0-9]+$", n)
	if err != nil {
		// TODO: handle this better
		zap.S().Warnf("matching service type: %v", err)
		return false
	}
	return matched
}

// Validate ensures that the required fields are set to reasonable values, usually just non-empty strings.
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

// Validate ensures that the required fields are set to reasonable values, usually just non-empty strings.
func (req *KubeConfigRequest) Validate() error {
	if !namePresent(req.AgentName) {
		return fmt.Errorf("'agentName' is invalid")
	}

	if !namePresent(req.Name) {
		return fmt.Errorf("'name' is invalid")
	}

	return nil
}

// Validate ensures that the required fields are set to reasonable values, usually just non-empty strings.
func (req *ManifestRequest) Validate() error {
	if !namePresent(req.AgentName) {
		return fmt.Errorf("'agentName' is invalid")
	}

	return nil
}

// Validate ensures that the required fields are set to reasonable values, usually just non-empty strings.
func (req *ControlCredentialsRequest) Validate() error {
	if !namePresent(req.Name) {
		return fmt.Errorf("'name' is invalid")
	}

	return nil
}
