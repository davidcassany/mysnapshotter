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
	"strings"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/davidcassany/ocistore/pkg/chunked"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// RangeResolver wraps a remotes.Resolver whose HTTP client is configured
// with rangeRoundTripper. Use its Fetcher method to obtain a RangeFetcher.
type RangeResolver struct {
	remotes.Resolver
}

// Fetcher returns a RangeFetcher for the given image reference.
func (r *RangeResolver) Fetcher(ctx context.Context, ref string) (RangeFetcher, error) {
	f, err := r.Resolver.Fetcher(ctx, ref)
	if err != nil {
		return RangeFetcher{}, err
	}
	return RangeFetcher{inner: f}, nil
}

// RangeFetcher is a remotes.Fetcher backed by a rangeRoundTripper-enabled
// HTTP client. Obtain one exclusively via RangeResolver.Fetcher so that
// FetchRange's range injection is guaranteed to be intercepted.
type RangeFetcher struct {
	inner remotes.Fetcher
}

// Fetch implements remotes.Fetcher.
func (f RangeFetcher) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	return f.inner.Fetch(ctx, desc)
}

func SetupOCIRegistryResolver(verify bool, opts *docker.ResolverOptions) *RangeResolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if !verify {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	customClient := &http.Client{
		Transport: &rangeRoundTripper{
			Base: transport,
		},
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

	return &RangeResolver{Resolver: docker.NewResolver(*opts)}
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

// Define a custom type for our context key to avoid collisions
type rangeContextKey struct{}

// rangeTarget holds the instructions for our RoundTripper
type rangeTarget struct {
	Digest string
	Offset int64
	Size   int64
}

// rangeRoundTripper intercepts requests and injects the Range header
type rangeRoundTripper struct {
	Base http.RoundTripper
}

func (rt *rangeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if the range target instructions are in the context
	target, ok := req.Context().Value(rangeContextKey{}).(rangeTarget)
	if !ok {
		// Not our target, proceed normally
		return rt.Base.RoundTrip(req)
	}

	// Check the request is a GET method including the Digest we want to fetch, then
	// assume this the request we want to intercept and recreate
	if strings.Contains(req.URL.Path, target.Digest) && req.Method == http.MethodGet {
		clonedReq := req.Clone(req.Context())
		bRange := fmt.Sprintf("bytes=%d-%d", target.Offset, target.Offset+target.Size-1)
		clonedReq.Header.Set("Range", bRange)
		return rt.Base.RoundTrip(clonedReq)
	}
	return rt.Base.RoundTrip(req)
}

func FetchRange(ctx context.Context, fetcher RangeFetcher, desc ocispec.Descriptor, offset int64, size int64) (io.ReadCloser, error) {
	target := rangeTarget{
		Digest: desc.Digest.Encoded(),
		Offset: offset,
		Size:   size,
	}
	ctxWithRange := context.WithValue(ctx, rangeContextKey{}, target)

	rc, err := fetcher.Fetch(ctxWithRange, desc)
	if err != nil {
		return nil, err
	}

	return rc, nil
}

func GetToCLocation(ctx context.Context, fetcher RangeFetcher, desc ocispec.Descriptor) (*chunked.TOCLocation, error) {
	loc, err := chunked.ParseAnnotations(desc.Annotations)
	if err != nil {
		//TODO add some logging to notify annotations are missing, not mandatory but desirable
	}

	r, err := FetchRange(ctx, fetcher, desc, desc.Size-chunked.FooterFrameSize, chunked.FooterFrameSize)
	if err != nil {
		return nil, fmt.Errorf("fetching footer frame range: %w", err)
	}
	fLoc, err := chunked.ParseFooterFrame(r)
	cErr := r.Close()
	if err != nil {
		return nil, fmt.Errorf("parsing footer frame location: %w", err)
	}
	if cErr != nil {
		return nil, fmt.Errorf("closing range reader: %w", cErr)
	}

	if loc != nil {
		if fLoc.Offset != loc.Offset ||
			fLoc.LengthCompressed != loc.LengthCompressed ||
			fLoc.LengthUncompressed != loc.LengthUncompressed {
			return nil, fmt.Errorf("inconsistent chunked annotations compared with the parsed footer")
		}
	}

	return fLoc, nil
}

func FetchToC(ctx context.Context, fetcher RangeFetcher, desc ocispec.Descriptor) (_ *chunked.TOC, err error) {
	loc, err := GetToCLocation(ctx, fetcher, desc)
	if err != nil {
		return nil, err
	}

	r, err := FetchRange(ctx, fetcher, desc, int64(loc.Offset), int64(loc.LengthCompressed))
	if err != nil {
		return nil, fmt.Errorf("fetching footer frame range: %w", err)
	}
	return chunked.ParseTOC(r, loc)
}
