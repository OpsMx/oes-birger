package secrets

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type SecretLoader interface {
	GetSecret(string) (*map[string][]byte, error)
}

type KubernetesSecretLoader struct {
	clientset *kubernetes.Clientset
	namespace string
}

func MakeKubernetesSecretsLoader(namespace string) (*KubernetesSecretLoader, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return makeClientset(namespace, config)
}

func MakeKubernetesSecretsLoaderFromKubectl(namespace string, kubeconfig string) (*KubernetesSecretLoader, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return makeClientset(namespace, config)
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

func (s *KubernetesSecretLoader) GetSecret(name string) (*map[string][]byte, error) {
	deploymentsClient := s.clientset.CoreV1().Secrets(s.namespace)

	secret, err := deploymentsClient.Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return &secret.Data, nil
}
