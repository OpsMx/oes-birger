package secrets

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
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func secret(name string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: "ns1",
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			"key1": []byte("key1 content"),
			"key2": []byte("key2 content"),
		},
	}
}

var (
	secret1Map = map[string][]byte{
		"key1": []byte("key1 content"),
		"key2": []byte("key2 content"),
	}
)

func TestKubernetesSecretLoader_GetSecret(t *testing.T) {
	var tests = []struct {
		description string
		secretName  string
		expected    *map[string][]byte
		objs        []runtime.Object
		wantErr     bool
	}{
		{
			"no secrets", "foo", nil, nil, true,
		},
		{
			"matching secret",
			"secret1", &secret1Map,
			[]runtime.Object{secret("secret1")},
			false,
		},
		{
			"non-matching secret",
			"secret2", nil,
			[]runtime.Object{secret("secret1")},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.objs...)
			loader := MakeKubernetesSecretLoaderFromClientset("ns1", client)

			actual, err := loader.GetSecret(test.secretName)
			if (err != nil) && !test.wantErr {
				t.Errorf("Unexpected error: %s", err)
				return
			}
			if (err == nil) && test.wantErr {
				t.Errorf("Expected an error, did not get one")
				return
			}
			if diff := cmp.Diff(actual, test.expected); diff != "" {
				t.Errorf("%T differ (-got, +want): %s", test.expected, diff)
				return
			}
		})
	}
}
