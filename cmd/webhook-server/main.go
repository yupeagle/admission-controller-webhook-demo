/*
Copyright (c) 2019 StackRox Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
        b64 "encoding/base64"
        "context"
	"errors"
	"fmt"
	"k8s.io/api/admission/v1beta1"
        "k8s.io/client-go/tools/clientcmd"
        "k8s.io/client-go/kubernetes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"net/http"
	"path/filepath"
        "strings"
)

const (
	tlsDir      = `/run/secrets/tls`
	tlsCertFile = `tls.crt`
	tlsKeyFile  = `tls.key`
)

var (
	podResource = metav1.GroupVersionResource{Version: "v1", Resource: "pods"}
)

// applySecurityDefaults implements the logic of our example admission controller webhook. For every pod that is created
// (outside of Kubernetes namespaces), it first checks if `runAsNonRoot` is set. If it is not, it is set to a default
// value of `false`. Furthermore, if `runAsUser` is not set (and `runAsNonRoot` was not initially set), it defaults
// `runAsUser` to a value of 1234.
//
// To demonstrate how requests can be rejected, this webhook further validates that the `runAsNonRoot` setting does
// not conflict with the `runAsUser` setting - i.e., if the former is set to `true`, the latter must not be `0`.
// Note that we combine both the setting of defaults and the check for potential conflicts in one webhook; ideally,
// the latter would be performed in a validating webhook admission controller.
func applySecurityDefaults(req *v1beta1.AdmissionRequest) ([]patchOperation, error) {
	// This handler should only get called on Pod objects as per the MutatingWebhookConfiguration in the YAML file.
	// However, if (for whatever reason) this gets invoked on an object of a different kind, issue a log message but
	// let the object request pass through otherwise.
	config, err := clientcmd.BuildConfigFromFlags("", "")
	clientset, err := kubernetes.NewForConfig(config)
        if err != nil {
		log.Fatal(err)
        }
	if req.Resource != podResource {
		log.Printf("expect resource to be %s", podResource)
		return nil, nil
	}
    log.Print("Into applySecurityDefaults")
	// Parse the Pod object.
	raw := req.Object.Raw
	pod := corev1.Pod{}
	if _, _, err := universalDeserializer.Decode(raw, nil, &pod); err != nil {
		return nil, fmt.Errorf("could not deserialize pod object: %v", err)
	}
	if !strings.Contains(req.UserInfo.Username, "@") {
                fmt.Printf("Requester: %s. Not from AD, passing\n", req.UserInfo.Username)
		return nil, nil
        }

	// Retrieve the `runAsNonRoot` and `runAsUser` values.
	// var runAsNonRoot *bool
	// var runAsUser *int64
	//var sparkJobOwner *string = pod.Metadata.labels
	/* if pod.Spec.SecurityContext != nil {
		runAsNonRoot = pod.Spec.SecurityContext.RunAsNonRoot
		runAsUser = pod.Spec.SecurityContext.RunAsUser
	} */
	getpod, err2 := clientset.CoreV1().Pods("default").Get(context.TODO(),"pod-with-defaults", metav1.GetOptions{})
	fmt.Printf("%#v\n", getpod)
	fmt.Printf("%#v\n", err2)
	fmt.Printf("=============================================")
	fmt.Printf("%#v\n", pod.ObjectMeta.Labels["sparkJobOwner"])
	fmt.Printf("%#v\n", pod)
	fmt.Printf("%#v\n", req.UserInfo.Username)
	owner, _ := b64.StdEncoding.DecodeString(pod.ObjectMeta.Labels["sparkJobOwner"])
	// Create patch operations to apply sensible defaults, if those options are not set explicitly.
	/*
        var patches []patchOperation
	if runAsNonRoot == nil {
		patches = append(patches, patchOperation{
			Op:    "add",
			Path:  "/spec/securityContext/runAsNonRoot",
			// The value must not be true if runAsUser is set to 0, as otherwise we would create a conflicting
			// configuration ourselves.
			Value: runAsUser == nil || *runAsUser != 0,
		})

		if runAsUser == nil {
			patches = append(patches, patchOperation{
				Op:    "add",
				Path:  "/spec/securityContext/runAsUser",
				Value: 1234,
			})
		}
	} else if *runAsNonRoot == true && (runAsUser != nil && *runAsUser == 0) {
		// Make sure that the settings are not contradictory, and fail the object creation if they are.
		return nil, errors.New("runAsNonRoot specified, but runAsUser set to 0 (the root user)")
	}
        */
        ownerTrimmed := strings.TrimSpace(string(owner))
        if ownerTrimmed != req.UserInfo.Username {
                errorMsg := fmt.Sprintf("You are mutating pods which are not owned by you, requester: %s, owner: %s, before: %s", req.UserInfo.Username, ownerTrimmed, string(owner))
		return nil, errors.New(errorMsg)
        }
	return nil, nil
}

func main() {
	certPath := filepath.Join(tlsDir, tlsCertFile)
	keyPath := filepath.Join(tlsDir, tlsKeyFile)

	mux := http.NewServeMux()
	mux.Handle("/mutate", admitFuncHandler(applySecurityDefaults))
	server := &http.Server{
		// We listen on port 8443 such that we do not need root privileges or extra capabilities for this server.
		// The Service object will take care of mapping this port to the HTTPS port 443.
		Addr:    ":8443",
		Handler: mux,
	}
	log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}
