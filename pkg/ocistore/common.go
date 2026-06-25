/*
Copyright © 2024 SUSE LLC

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

package ocistore

import (
	"crypto/tls"
	"net/http"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
)

func SetupOCIRegistryResolver(verify bool, opts *docker.ResolverOptions) remotes.Resolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if !verify {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	customClient := &http.Client{
		Transport: transport,
	}

	authorizer := docker.NewDockerAuthorizer(
		docker.WithAuthClient(customClient),
		docker.WithAuthCreds(func(host string) (string, string, error) {
			// Returning empty credentials triggers the anonymous bearer token request
			// needed for public images on Docker Hub.
			return "", "", nil
		}),
	)

	// Initialize the resolver with our customized client
	if opts == nil {
		opts = &docker.ResolverOptions{
			Hosts: docker.ConfigureDefaultRegistries(
				docker.WithClient(customClient),
				docker.WithAuthorizer(authorizer),
			),
		}
	} else {
		opts.Hosts = docker.ConfigureDefaultRegistries(
			docker.WithClient(customClient),
			docker.WithAuthorizer(authorizer),
		)
	}

	return docker.NewResolver(*opts)
}
