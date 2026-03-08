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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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

	registryOpts := []docker.RegistryOpt{
		docker.WithClient(customClient),
		docker.WithAuthorizer(authorizer),
	}
	if !verify {
		registryOpts = append(registryOpts, docker.WithPlainHTTP(docker.MatchAllHosts))
	}

	// Initialize the resolver with our customized client
	if opts == nil {
		opts = &docker.ResolverOptions{
			Hosts: docker.ConfigureDefaultRegistries(registryOpts...),
		}
	} else {
		opts.Hosts = docker.ConfigureDefaultRegistries(registryOpts...)
	}

	return docker.NewResolver(*opts)
}

// FetchMetadata uses the fetcher to grab a blob and returns blob bytes.
// This is strictly used for the small non-layer blobs (Manifest and Config).
func FetchMetadata(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor) (metadata []byte, err error) {
	if images.IsLayerType(desc.MediaType) {
		return nil, fmt.Errorf("FetchMetadata called with a layer descriptor (media type %q): only Manifest and Config descriptors are supported", desc.MediaType)
	}

	// Fetch from the registry
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata blob %s: %w", desc.Digest, err)
	}
	defer func() {
		cerr := rc.Close()
		if err == nil && cerr != nil {
			err = cerr
		}
	}()

	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading remote io Reader: %w", err)
	}
	return b, nil
}
