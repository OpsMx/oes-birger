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

import (
	"testing"

	"github.com/opsmx/oes-birger/internal/jwtutil"
	"github.com/skandragon/jwtregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestMakeHeaders_NoMutation(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		wantRet []*HttpHeader
		wantErr bool
	}{
		{
			"empty headers",
			map[string][]string{},
			[]*HttpHeader{},
			false,
		},
		{
			"one item",
			map[string][]string{"foo": {"bar"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
			},
			false,
		},
		{
			"two items",
			map[string][]string{"foo": {"bar"}, "baz": {"bax"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
				{Name: "baz", Values: []string{"bax"}},
			},
			false,
		},
		{
			"one item, two values",
			map[string][]string{"foo": {"bar", "baz"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar", "baz"}},
			},
			false,
		},
		{
			"does not mutate mutatable headers if not registered",
			map[string][]string{mutatedHeaders[0]: {"bar"}},
			[]*HttpHeader{
				{Name: mutatedHeaders[0], Values: []string{"bar"}},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRet, err := MakeHeaders(tt.headers)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantRet, gotRet)
		})
	}
}

func TestMakeHeaders_Mutation(t *testing.T) {
	jwtregistry.Clear()
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterMutationKeyset(keyset, "key1")
	require.NoError(t, err)

	tests := []struct {
		name    string
		headers map[string][]string
		wantRet []*HttpHeader
		wantErr bool
	}{
		{
			"empty headers",
			map[string][]string{},
			[]*HttpHeader{},
			false,
		},
		{
			"one item",
			map[string][]string{"foo": {"bar"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
			},
			false,
		},
		{
			"two items",
			map[string][]string{"foo": {"bar"}, "baz": {"bax"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
				{Name: "baz", Values: []string{"bax"}},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRet, err := MakeHeaders(tt.headers)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantRet, gotRet)
		})
	}

	// special cases for testing actual mutations
	t.Run("mutates properly", func(t *testing.T) {
		got, err := MakeHeaders(map[string][]string{mutatedHeaders[0]: {"bar"}})
		require.NoError(t, err)
		// we don't have control over the signing clock here, so we will just check
		// that it looks like a JWT, and has the proper number of elements.
		assert.Equal(t, 1, len(got), "expected slice length 1")
		name, values := got[0].Name, got[0].Values
		assert.Equal(t, "X-Spinnaker-User", name)
		assert.Equal(t, 1, len(values), "expected one value")
	})

	// test that only the first element is mutated
	t.Run("mutates properly, more than one item", func(t *testing.T) {
		got, err := MakeHeaders(map[string][]string{mutatedHeaders[0]: {"bar", "baz"}})
		require.NoError(t, err)
		// we don't have control over the signing clock here, so we will just check
		// that it looks like a JWT, and has the proper number of elements.
		assert.Equal(t, 1, len(got), "expected slice length 1")
		name, values := got[0].Name, got[0].Values
		assert.Equal(t, "X-Spinnaker-User", name)
		assert.Equal(t, 1, len(values), "expected one value")
	})
}
