package kubeconfig

import (
	"strings"
	"testing"
)

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

func TestSimpleFileLoads(t *testing.T) {
	contents := `
apiVersion: v1
kind: Config
`
	_, err := ReadKubeConfig(strings.NewReader(contents))
	if err != nil {
		t.Errorf("Got an unexpected error: %v", err)
	}
}
