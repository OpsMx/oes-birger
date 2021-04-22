package util

import "fmt"

type Versions struct {
	Major int
	Minor int
	Patch int
	Build int
}

func (v *Versions) String() string {
	if v.Build > 0 {
		return fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Patch, v.Build)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
