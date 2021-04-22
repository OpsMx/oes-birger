package util

import "testing"

func TestVersions_String(t *testing.T) {
	type fields struct {
		Major int
		Minor int
		Patch int
		Build int
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			"build isn't there",
			fields{Major: 1, Minor: 2, Patch: 3},
			"1.2.3",
		},
		{
			"build is -1 there",
			fields{Major: 1, Minor: 2, Patch: 3, Build: -1},
			"1.2.3",
		},
		{
			"build is valid",
			fields{Major: 999, Minor: 2, Patch: 3, Build: 99},
			"999.2.3.99",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Versions{
				Major: tt.fields.Major,
				Minor: tt.fields.Minor,
				Patch: tt.fields.Patch,
				Build: tt.fields.Build,
			}
			if got := v.String(); got != tt.want {
				t.Errorf("Versions.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
