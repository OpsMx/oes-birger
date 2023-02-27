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

// Package secrets loads secrets from various sources, such as Kubernetes
// secrets.
package secrets

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesSecretLoader will load a secret from a Kubernetes namesapce.
type KubernetesSecretLoader struct {
	clientset kubernetes.Interface
	namespace string
}

// MakeKubernetesSecretLoader returns a new KubenetesSecretLoader using the Kubernetes service
// account.
func MakeKubernetesSecretLoader(namespace string) (*KubernetesSecretLoader, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return makeClientset(namespace, config)
}

// MakeKubernetesSecretLoaderFromKubectl returns a new KubernetesSecretLoader that uses
// credentials in the provided kubeconfig credentials.
func MakeKubernetesSecretLoaderFromKubectl(namespace string, kubeconfig string) (*KubernetesSecretLoader, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return makeClientset(namespace, config)
}

// MakeKubernetesSecretLoaderFromClientset creates a new KubernetesSecretLoader from a
// clientset.
func MakeKubernetesSecretLoaderFromClientset(namespace string, clientset kubernetes.Interface) *KubernetesSecretLoader {
	return &KubernetesSecretLoader{
		clientset: clientset,
		namespace: namespace,
	}
}

func makeClientset(namespace string, config *rest.Config) (*KubernetesSecretLoader, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &KubernetesSecretLoader{
		clientset: clientset,
		namespace: namespace,
	}, nil
}

// GetSecret will return a secret from Kubernetes, as a map.
func (s *KubernetesSecretLoader) GetSecret(name string) (*map[string][]byte, error) {
	deploymentsClient := s.clientset.CoreV1().Secrets(s.namespace)

	secret, err := deploymentsClient.Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return &secret.Data, nil
}
