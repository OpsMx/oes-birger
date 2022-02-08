/*
 * Copyright 2022 OpsMx, Inc.
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

package tunnel

import "testing"

func Test_containsFolded(t *testing.T) {
	type args struct {
		l []string
		t string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"empty list", args{[]string{}, "foo"}, false},
		{"not in list", args{[]string{"bar"}, "foo"}, false},
		{"in list case exact", args{[]string{"bar", "foo"}, "foo"}, true},
		{"in list, list upper", args{[]string{"bar", "FOO"}, "foo"}, true},
		{"in list, target upper", args{[]string{"bar", "foo"}, "Foo"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsFolded(tt.args.l, tt.args.t); got != tt.want {
				t.Errorf("containsFolded() = %v, want %v", got, tt.want)
			}
		})
	}
}
