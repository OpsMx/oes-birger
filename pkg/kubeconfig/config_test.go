package kubeconfig

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
	"strings"
	"testing"
)

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func TestApiVersion1(t *testing.T) {
	contents := `
kind: Config
`
	_, err := ReadKubeConfig(strings.NewReader(contents))
	if err == nil {
		t.Errorf("Expected err to be set")
	} else if !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("Got %v", err)
	}
}

func TestApiVersion2(t *testing.T) {
	contents := `
apiVersion: foo
kind: Config
`
	_, err := ReadKubeConfig(strings.NewReader(contents))
	if err == nil {
		t.Errorf("Expected err to be set")
	} else if !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("Got %v", err)
	}
}

func TestKind1(t *testing.T) {
	contents := `
apiVersion: v1
`
	_, err := ReadKubeConfig(strings.NewReader(contents))
	if err == nil {
		t.Errorf("Expected err to be set")
	} else if !strings.Contains(err.Error(), "kind") {
		t.Errorf("Got %v", err)
	}
}

func TestKind2(t *testing.T) {
	contents := `
apiVersion: v1
kind: Foo
`
	_, err := ReadKubeConfig(strings.NewReader(contents))
	if err == nil {
		t.Errorf("Expected err to be set")
	} else if !strings.Contains(err.Error(), "kind") {
		t.Errorf("Got %v", err)
	}
}

const simpleConfig = `
apiVersion: v1
kind: Config
`

func TestSimpleFileLoads(t *testing.T) {
	_, err := ReadKubeConfig(strings.NewReader(simpleConfig))
	if err != nil {
		t.Errorf("Got an unexpected error: %v", err)
	}
}

func TestEmptyContextNames(t *testing.T) {
	kc, err := ReadKubeConfig(strings.NewReader(simpleConfig))
	if err != nil {
		t.Errorf("Got an unexpected error: %v", err)
		return
	}
	names := kc.GetContextNames()
	if len(names) != 0 {
		t.Error("Expected names for a simple config to be empty")
	}
}

func TestGetContextNames(t *testing.T) {
	contents := `
apiVersion: v1
kind: Config
contexts:
- context:
  name: contextOne
- context:
  name: contextTwo
- context:
  name: contextThree
`

	kc, err := ReadKubeConfig(strings.NewReader(contents))
	if err != nil {
		t.Errorf("Got an unexpected error: %v", err)
		return
	}
	names := kc.GetContextNames()
	if len(names) != 3 {
		t.Errorf("Expected 3 context names, found only %d", len(names))
	}
	if !contains(names, "contextOne") {
		t.Error("Expected context names to include 'contextOne'")
	}
	if !contains(names, "contextTwo") {
		t.Error("Expected context names to include 'contextTwo'")
	}
	if !contains(names, "contextThree") {
		t.Error("Expected context names to include 'contextThree'")
	}
}

func TestGetRequiresUser(t *testing.T) {
	contents := `
apiVersion: v1
kind: Config
contexts:
- name: contextOne
  context:
    cluster: clusterOne
`

	kc, err := ReadKubeConfig(strings.NewReader(contents))
	if err != nil {
		t.Errorf("Got an unexpected error: %v", err)
		return
	}
	_, _, err = kc.FindContext("contextOne")
	if !strings.Contains(err.Error(), "no user") {
		t.Errorf("Epected 'no user' in error, got %v", err)
	}
}
func TestGetRequiresCluster(t *testing.T) {
	contents := `
apiVersion: v1
kind: Config
contexts:
- name: contextOne
  context:
    user: userOne
`

	kc, err := ReadKubeConfig(strings.NewReader(contents))
	if err != nil {
		t.Errorf("Got an unexpected error: %v", err)
		return
	}
	_, _, err = kc.FindContext("contextOne")
	if !strings.Contains(err.Error(), "no cluster") {
		t.Errorf("Epected 'no cluster' in error, got %v", err)
	}
}

func TestGetRequiresClusterToExist(t *testing.T) {
	contents := `
apiVersion: v1
kind: Config
contexts:
- name: contextOne
  context:
    user: userOne
    cluster: clusterOne
users:
- name: userOne
  user:
    client-certificate-data: AAA
    client-key-data: AAA
clusters:
- name: clusterOne
  cluster:
    certificate-authority-data: AAA
    server: https://example.com:6443
`

	kc, err := ReadKubeConfig(strings.NewReader(contents))
	if err != nil {
		t.Errorf("Got an unexpected error: %v", err)
		return
	}
	user, cluster, err := kc.FindContext("contextOne")
	if err != nil {
		t.Errorf("Got an unexpected error: %v", err)
		return
	}
	if user.Name != "userOne" {
		t.Errorf("Found user named '%s' but expected 'userOne'", user.Name)
	}
	if cluster.Name != "clusterOne" {
		t.Errorf("Found cluster named '%s' but expected 'clusterOne'", cluster.Name)
	}
}
