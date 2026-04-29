package kube

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	StateConfigMapName    = "rke2-patcher-state"
	StateConfigMapDataKey = "patch-limit-state.json"
)

// LoadStateConfigMapData returns the string value stored at key in the ConfigMap.
// If the ConfigMap or key does not exist, it returns an empty string and no error.
func LoadStateConfigMapData(namespace string) (string, error) {
	value, _, err := LoadStateConfigMapDataWithResourceVersion(namespace)
	if err != nil {
		return "", err
	}

	return value, nil
}

// LoadStateConfigMapDataWithResourceVersion returns the value stored at key and the
// ConfigMap resourceVersion used for optimistic concurrency.
// If the ConfigMap or key does not exist, it returns an empty value and no error.
func LoadStateConfigMapDataWithResourceVersion(namespace string) (string, string, error) {
	clientset, err := ClientsetProvider()
	if err != nil {
		return "", "", err
	}

	configMap, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), StateConfigMapName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("failed to read state ConfigMap %s/%s: %w", namespace, StateConfigMapName, err)
	}

	if configMap.Data == nil {
		return "", configMap.ResourceVersion, nil
	}

	return configMap.Data[StateConfigMapDataKey], configMap.ResourceVersion, nil
}

// SaveStateConfigMapDataWithResourceVersion writes key/value to the ConfigMap only
// if expectedResourceVersion still matches the current object. When expectedResourceVersion
// is empty, it only succeeds if the ConfigMap does not yet exist.
func SaveStateConfigMapDataWithResourceVersion(namespace string, value string, expectedResourceVersion string) error {
	clientset, err := ClientsetProvider()
	if err != nil {
		return err
	}

	current, getErr := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), StateConfigMapName, metav1.GetOptions{})
	if getErr != nil {
		if !k8serrors.IsNotFound(getErr) {
			return fmt.Errorf("failed to read state ConfigMap %s/%s: %w", namespace, StateConfigMapName, getErr)
		}

		if expectedResourceVersion != "" {
			return k8serrors.NewConflict(corev1.Resource("configmaps"), StateConfigMapName, fmt.Errorf("state ConfigMap %s/%s was deleted", namespace, StateConfigMapName))
		}

		toCreate := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      StateConfigMapName,
				Namespace: namespace,
			},
			Data: map[string]string{StateConfigMapDataKey: value},
		}

		if _, createErr := clientset.CoreV1().ConfigMaps(namespace).Create(context.Background(), toCreate, metav1.CreateOptions{}); createErr != nil {
			return fmt.Errorf("failed to create state ConfigMap %s/%s: %w", namespace, StateConfigMapName, createErr)
		}

		return nil
	}

	if expectedResourceVersion == "" || current.ResourceVersion != expectedResourceVersion {
		return k8serrors.NewConflict(corev1.Resource("configmaps"), StateConfigMapName, fmt.Errorf("state ConfigMap %s/%s changed while persisting", namespace, StateConfigMapName))
	}

	updated := current.DeepCopy()
	if updated.Data == nil {
		updated.Data = map[string]string{}
	}
	updated.Data[StateConfigMapDataKey] = value

	if _, updateErr := clientset.CoreV1().ConfigMaps(namespace).Update(context.Background(), updated, metav1.UpdateOptions{}); updateErr != nil {
		return fmt.Errorf("failed to update state ConfigMap %s/%s: %w", namespace, StateConfigMapName, updateErr)
	}

	return nil
}

// SaveStateConfigMapData writes key/value to the ConfigMap, creating it if it does not exist.
func SaveStateConfigMapData(namespace string, value string) error {
	clientset, err := ClientsetProvider()
	if err != nil {
		return err
	}

	for attempt := 0; attempt < 3; attempt++ {
		current, getErr := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), StateConfigMapName, metav1.GetOptions{})
		if getErr != nil {
			if !k8serrors.IsNotFound(getErr) {
				return fmt.Errorf("failed to read state ConfigMap %s/%s: %w", namespace, StateConfigMapName, getErr)
			}

			toCreate := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      StateConfigMapName,
					Namespace: namespace,
				},
				Data: map[string]string{StateConfigMapDataKey: value},
			}

			if _, createErr := clientset.CoreV1().ConfigMaps(namespace).Create(context.Background(), toCreate, metav1.CreateOptions{}); createErr == nil {
				return nil
			} else if k8serrors.IsAlreadyExists(createErr) || k8serrors.IsConflict(createErr) {
				continue
			} else {
				return fmt.Errorf("failed to create state ConfigMap %s/%s: %w", namespace, StateConfigMapName, createErr)
			}
		}

		updated := current.DeepCopy()
		if updated.Data == nil {
			updated.Data = map[string]string{}
		}
		updated.Data[StateConfigMapDataKey] = value

		if _, updateErr := clientset.CoreV1().ConfigMaps(namespace).Update(context.Background(), updated, metav1.UpdateOptions{}); updateErr == nil {
			return nil
		} else if k8serrors.IsConflict(updateErr) {
			continue
		} else {
			return fmt.Errorf("failed to update state ConfigMap %s/%s: %w", namespace, StateConfigMapName, updateErr)
		}
	}

	return fmt.Errorf("failed to persist state ConfigMap %s/%s after retries", namespace, StateConfigMapName)
}
