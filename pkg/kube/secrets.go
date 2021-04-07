package secrets

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type SecretsLoader struct {
	clientset *kubernetes.Clientset
	namespace string
}

func MakeSecretsLoader(namespace string) (*SecretsLoader, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return makeClientset(namespace, config)
}

func MakeSecretsLoaderFromKubectl(namespace string, kubeconfig string) (*SecretsLoader, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return makeClientset(namespace, config)
}

func makeClientset(namespace string, config *rest.Config) (*SecretsLoader, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &SecretsLoader{
		clientset: clientset,
		namespace: namespace,
	}, nil
}

func (s *SecretsLoader) GetSecret(name string) (map[string][]byte, error) {
	deploymentsClient := s.clientset.CoreV1().Secrets(s.namespace)

	secret, err := deploymentsClient.Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return map[string][]byte{}, err
	}
	return secret.Data, nil
}
