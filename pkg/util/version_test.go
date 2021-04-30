package util

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
