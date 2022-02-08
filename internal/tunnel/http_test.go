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
	"net/http"
	"testing"

	"github.com/opsmx/oes-birger/internal/jwtutil"
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
	jwtutil.UnregisterMutationKeyset()
	tests := []struct {
		name    string
		headers map[string][]string
		wantRet []*HttpHeader
	}{
		{
			"empty headers",
			map[string][]string{},
			[]*HttpHeader{},
		},
		{
			"one item",
			map[string][]string{"foo": {"bar"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
			},
		},
		{
			"two items",
			map[string][]string{"foo": {"bar"}, "baz": {"bax"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
				{Name: "baz", Values: []string{"bax"}},
			},
		},
		{
			"one item, two values",
			map[string][]string{"foo": {"bar", "baz"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar", "baz"}},
			},
		},
		{
			"does not mutate mutatable headers if not registered",
			map[string][]string{mutatedHeaders[0]: {"bar"}},
			[]*HttpHeader{
				{Name: mutatedHeaders[0], Values: []string{"bar"}},
			},
		},
		{
			"strips",
			map[string][]string{
				strippedOutgoingHeaders[0]: {"bar"},
				"foo":                      {"bar"},
			},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRet, err := MakeHeaders(tt.headers)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantRet, gotRet)
		})
	}
}

func TestMakeHeaders_Mutation(t *testing.T) {
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterMutationKeyset(keyset, "key1")
	require.NoError(t, err)

	tests := []struct {
		name    string
		headers map[string][]string
		wantRet []*HttpHeader
	}{
		{
			"empty headers",
			map[string][]string{},
			[]*HttpHeader{},
		},
		{
			"one item",
			map[string][]string{"foo": {"bar"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
			},
		},
		{
			"two items",
			map[string][]string{"foo": {"bar"}, "baz": {"bax"}},
			[]*HttpHeader{
				{Name: "foo", Values: []string{"bar"}},
				{Name: "baz", Values: []string{"bax"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRet, err := MakeHeaders(tt.headers)
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

func TestMakeHeaders_MutationBroken(t *testing.T) {
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterMutationKeyset(keyset, "keynotthere")
	require.NoError(t, err)

	// special cases for testing actual mutations where it can't mutate due to broken jwtregistry
	t.Run("errors", func(t *testing.T) {
		_, err := MakeHeaders(map[string][]string{mutatedHeaders[0]: {"bar"}})
		require.Error(t, err)
	})
}

func TestCopyHeaders_NoUnmutate(t *testing.T) {
	jwtutil.UnregisterMutationKeyset()
	tests := []struct {
		name        string
		headers     []*HttpHeader
		wantHeaders http.Header
	}{
		{
			"one item",
			[]*HttpHeader{
				{Name: "bob", Values: []string{"baz"}},
			},
			http.Header{
				"Bob": {"baz"}, // note case is expected
			},
		},
		{
			"one item, two values",
			[]*HttpHeader{
				{Name: "bob", Values: []string{"baz", "bar"}},
			},
			http.Header{
				"Bob": {"baz", "bar"}, // note case is expected
			},
		},
		{
			"two items",
			[]*HttpHeader{
				{Name: "alice", Values: []string{"foo"}},
				{Name: "bob", Values: []string{"baz"}},
			},
			http.Header{
				"Alice": {"foo"},
				"Bob":   {"baz"},
			},
		},
		{
			"one item, mutatable header, not mutated due to no registry entry",
			[]*HttpHeader{
				{Name: mutatedHeaders[0], Values: []string{"baz"}},
			},
			http.Header{
				mutatedHeaders[0]: {"baz"}, // note case is expected
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := http.Header{}
			err := CopyHeaders(tt.headers, &got)
			require.NoError(t, err)
			assert.Equal(t, tt.wantHeaders, got)
		})
	}
}

func TestCopyHeaders_Unmutate(t *testing.T) {
	keyset := jwtutil.LoadTestKeys(t)
	err := jwtutil.RegisterMutationKeyset(keyset, "key1")
	require.NoError(t, err)
	tests := []struct {
		name        string
		headers     []*HttpHeader
		wantHeaders http.Header
		wantErr     bool
	}{
		{
			"one item",
			[]*HttpHeader{
				{Name: "bob", Values: []string{"baz"}},
			},
			http.Header{
				"Bob": {"baz"}, // note case is expected
			},
			false,
		},
		{
			"one item, mutatable header, unmutated",
			[]*HttpHeader{
				{Name: mutatedHeaders[0], Values: []string{"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWhlYWRlci1tdXRhdGlvbiIsInUiOiJhbGljZSJ9.Qm6oubKqTW7ZHQ0IB8lc_04Nnqj_jXEeNECBy-06to4"}},
			},
			http.Header{
				mutatedHeaders[0]: {"alice"},
			},
			false,
		},
		{
			"two items, one mutatable header, unmutated",
			[]*HttpHeader{
				{Name: "bob", Values: []string{"baz"}},
				{Name: mutatedHeaders[0], Values: []string{"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWhlYWRlci1tdXRhdGlvbiIsInUiOiJhbGljZSJ9.Qm6oubKqTW7ZHQ0IB8lc_04Nnqj_jXEeNECBy-06to4"}},
			},
			http.Header{
				"Bob":             {"baz"},
				mutatedHeaders[0]: {"alice"},
			},
			false,
		},
		{
			"one item, mutatable header, only first item unmutated",
			[]*HttpHeader{
				{Name: mutatedHeaders[0], Values: []string{
					"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWhlYWRlci1tdXRhdGlvbiIsInUiOiJhbGljZSJ9.Qm6oubKqTW7ZHQ0IB8lc_04Nnqj_jXEeNECBy-06to4",
					"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6Im9wc214LWhlYWRlci1tdXRhdGlvbiIsInUiOiJib2IifQ.6BcMt4RWXr2dO7v-t_hEHmWKfCjqUbqOeZ4_z5mFIjE",
				}},
			},
			http.Header{
				mutatedHeaders[0]: {"alice"},
			},
			false,
		},
		{
			"one item, mutatable header, junk in",
			[]*HttpHeader{
				{Name: mutatedHeaders[0], Values: []string{"nota-token.nota-token.notatoken"}},
			},
			http.Header{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := http.Header{}
			err := CopyHeaders(tt.headers, &got)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantHeaders, got)
		})
	}
}
