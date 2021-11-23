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

package tunnelroute

import "testing"

func TestEndpoint_String(t *testing.T) {
	type fields struct {
		Name       string
		Type       string
		Configured bool
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			"test1",
			fields{Name: "name1", Type: "type1", Configured: true},
			"(type1, name1, true)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{
				Name:       tt.fields.Name,
				Type:       tt.fields.Type,
				Configured: tt.fields.Configured,
			}
			if got := e.String(); got != tt.want {
				t.Errorf("Endpoint.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
