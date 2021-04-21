package main

import "fmt"

type Versions struct {
	major int
	minor int
	patch int
	build int
}

var (
	versionBuild = -1
	version      = Versions{major: 2, minor: 0, patch: 1, build: versionBuild}
)

func (v *Versions) String() string {
	if v.build >= 0 {
		return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
	}
	return fmt.Sprintf("%d.%d.%d.%d", v.major, v.minor, v.patch, v.build)
}
