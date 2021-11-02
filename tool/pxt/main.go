/*
Copyright 2021 Pure Storage

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
	"context"
	"fmt"
	"os"

	"flag"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/sirupsen/logrus"

	teleport "github.com/gravitational/teleport/api/client"
	tc "github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/identityfile"
)

type Opts struct {
	Kubeconfig            string
	Cluster               string
	TeleportProxyPort     string
	TeleportServer        string
	TeleportKubeProxyPort string
	TeleportIdentityFile  string
}

var (
	opts Opts
)

func init() {
	flag.StringVar(&opts.Kubeconfig, "pxt.kubeconfig", "kubeconfig", "Output kubeconfig")
	flag.StringVar(&opts.Cluster, "pxt.cluster", "", "K8S Cluster name")
	flag.StringVar(&opts.TeleportProxyPort, "pxt.proxy-port", "3080", "Teleport proxy port")
	flag.StringVar(&opts.TeleportServer, "pxt.server", "ip-70-0-0-129.brbnca.spcsdns.net", "Teleport server")
	flag.StringVar(&opts.TeleportKubeProxyPort, "pxt.kube-proxy-port", "3026", "Teleport proxy server")
	flag.StringVar(&opts.TeleportIdentityFile, "pxt.identity", "", "Teleport identity file")
}

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()

	// Load teleport credentials from $HOME/.tsh
	creds := teleport.LoadProfile("", "")

	// Use a teleport cert identity file if supplied
	if opts.TeleportIdentityFile != "" {
		creds = teleport.LoadIdentityFile(opts.TeleportIdentityFile)
	}

	// Connect to Teleport
	proxy := opts.TeleportServer + ":" + opts.TeleportProxyPort
	clt, err := teleport.New(ctx, client.Config{
		Addrs: []string{
			proxy,
		},
		Credentials: []client.Credentials{
			creds,
		},
		InsecureAddressDiscovery: true,
	})
	if err != nil {
		logrus.Fatalf("failed to load teleport client: %v", err)
	}
	defer clt.Close()

	// Test Teleport connection
	resp, err := clt.Ping(ctx)
	if err != nil {
		logrus.Fatalf("failed to ping server %s: %v", proxy, err)
	}
	logrus.Infof("Teleport server response: %v", resp)

	// Get Kubernetes services
	services, err := clt.GetKubeServices(ctx)
	if err != nil {
		logrus.Fatalf("failed to get kube services: %v", err)
	}

	// Choose a cluster
	kubeCluster := ""
	for _, service := range services {
		clusters := service.GetKubernetesClusters()

		// Show available k8s clusters
		for _, cluster := range clusters {
			logrus.Infof("Available kube cluster: %s", cluster.Name)
			if opts.Cluster == "" {
				// for the demo, just pick one
				kubeCluster = cluster.Name
				logrus.Infof("Using kube cluster %s but you can supply your own on the arguments", cluster.Name)
				break
			} else if cluster.Name == opts.Cluster {
				kubeCluster = cluster.Name
				break
			}
		}

		if kubeCluster != "" {
			break
		}
	}
	if kubeCluster == "" {
		fmt.Printf("Kubernetes cluster %s not found\n", opts.Cluster)
		os.Exit(1)
	}

	// Generate new keys
	key, err := tc.NewKey()
	if err != nil {
		logrus.Fatalf("failed to generate keys: %v", err)
	}

	// Generate a new key pair
	ikey, err := tc.KeyFromIdentityFile(opts.TeleportIdentityFile)
	if err != nil {
		logrus.Fatalf("failed to get identity keys: %v", err)
	}

	// Get the user
	username, err := ikey.CertUsername()
	if err != nil {
		logrus.Errorf("failed to get user name from identity: %v", err)
	}
	logrus.Infof("Cert user is %s", username)

	// Setup the Teleport cluster name
	if key.ClusterName == "" {
		key.ClusterName = opts.TeleportServer
	}

	// Ask Teleport server for new certs
	certs, err := clt.GenerateUserCerts(ctx, proto.UserCertsRequest{
		PublicKey:      key.Pub,
		Username:       username,
		Expires:        time.Now().UTC().Add(time.Hour),
		RouteToCluster: key.ClusterName,

		// For this k8s cluster
		KubernetesCluster: kubeCluster,
	})
	if err != nil {
		logrus.Fatalf("failed to generate keys: %v", err)
	}
	key.Cert = certs.SSH
	key.TLSCert = certs.TLS
	key.TrustedCA = ikey.TrustedCA

	// Write kubeconfig
	filesWritten, err := identityfile.Write(identityfile.WriteConfig{
		OutputPath:           opts.Kubeconfig,
		Key:                  key,
		Format:               identityfile.FormatKubernetes,
		KubeProxyAddr:        "https://" + opts.TeleportServer + ":" + opts.TeleportKubeProxyPort,
		OverwriteDestination: true,
	})
	logrus.Infof("kubeconfig written to %v", filesWritten)

	// ----------------------------------
	// Use the kubeconfig
	// ----------------------------------

	// Kubernetes
	config, err := clientcmd.BuildConfigFromFlags("", "./kubeconfig")
	if err != nil {
		logrus.Fatalf("failed to config Kubernetes connection: %v", err)
	}

	clientset := kubernetes.NewForConfigOrDie(config)
	v, err := clientset.Discovery().ServerVersion()
	if err != nil {
		logrus.Fatalf("Unable to determine Kubernetes version: %v", err)
	}

	logrus.Infof("Kube Version: %s", v.String())
}
