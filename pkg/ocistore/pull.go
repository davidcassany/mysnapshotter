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
	"errors"
	"fmt"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
)

// RemoteContextOpt configures a RemoteContext without requiring a containerd client.
type RemoteContextOpt func(*client.RemoteContext) error

type PullOpts struct {
	aOpts   []ApplyCommitOpt
	rcOpts  []RemoteContextOpt
	unpack  bool
	skipTLS bool
}

type PullOpt func(*PullOpts) error

// WithRemoteContextOpts appends options that configure the RemoteContext used during fetch.
func WithRemoteContextOpts(opts ...RemoteContextOpt) PullOpt {
	return func(pOpts *PullOpts) error {
		pOpts.rcOpts = append(pOpts.rcOpts, opts...)
		return nil
	}
}

// AdaptRemoteOpt wraps a containerd client.RemoteOpt as a RemoteContextOpt.
// Only safe for opts that do not use the *Client argument (most built-in ones do not).
func AdaptRemoteOpt(opt client.RemoteOpt) RemoteContextOpt {
	return func(rc *client.RemoteContext) error {
		return opt(nil, rc)
	}
}

func WithPullUnpack() PullOpt {
	return func(pOpts *PullOpts) error {
		pOpts.unpack = true
		return nil
	}
}

func WithSkipTLS() PullOpt {
	return func(pOpts *PullOpts) error {
		pOpts.skipTLS = true
		return nil
	}
}

func WithPullApplyCommitOpts(opts ...ApplyCommitOpt) PullOpt {
	return func(pOpts *PullOpts) error {
		pOpts.aOpts = append(pOpts.aOpts, opts...)
		return nil
	}
}

func (c *OCIStore) Pull(ref string, opts ...PullOpt) (_ *images.Image, retErr error) {
	if !c.IsInitiated() {
		return nil, errors.New(missInitErrMsg)
	}

	pOpt := &PullOpts{
		aOpts:  []ApplyCommitOpt{},
		rcOpts: []RemoteContextOpt{},
	}
	for _, o := range opts {
		err := o(pOpt)
		if err != nil {
			return nil, err
		}
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to pull image: %v", err)
		return nil, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on pull operation")
		}
	}()

	img, err := /*c.cli.Fetch(ctx, ref, pOpt.rOpts...) */ c.newFetch(ctx, ref, pOpt)
	if err != nil {
		c.log.Errorf("failed to pull image '%s': %v", ref, err)
		return nil, err
	}

	c.log.Infof("Successfully pulled image '%s'", img.Name)

	if pOpt.unpack {
		err = c.unpack(ctx, &img, pOpt.aOpts...)
		if err != nil {
			c.log.Errorf("failed to unpack image '%s': %v", img.Name, err)
		} else {
			c.log.Infof("Successfully unpacked image '%s'", img.Name)
		}
	}
	return &img, err
}

func (c *OCIStore) newFetch(ctx context.Context, ref string, pOpts *PullOpts) (img images.Image, err error) {
	resolver := SetupOCIRegistryResolver(!pOpts.skipTLS, nil)

	rCtx := &client.RemoteContext{}
	for _, o := range pOpts.rcOpts {
		if err = o(rCtx); err != nil {
			return images.Image{}, err
		}
	}

	name, desc, err := resolver.Resolve(c.ctx, ref)
	if err != nil {
		c.log.Errorf("failed resolving image reference into a name and OCI descriptor: %v", err)
		return img, fmt.Errorf("resolving image reference %q into a name and an OCI descriptor: %w", ref, err)
	}

	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return img, fmt.Errorf("initiating fetcher for image %s: %w", name, err)
	}

	var (
		handler images.Handler

		isConvertible bool
		converterFunc func(context.Context, ocispec.Descriptor) (ocispec.Descriptor, error)
		limiter       *semaphore.Weighted
	)
	if desc.MediaType == images.MediaTypeDockerSchema1Manifest {
		return images.Image{}, fmt.Errorf("%w: media type %q is no longer supported since containerd v2.1, please rebuild the image as %q or %q",
			errdefs.ErrNotImplemented,
			images.MediaTypeDockerSchema1Manifest, images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest)
	}
	// Get all the children for a descriptor
	childrenHandler := images.ChildrenHandler(c.cs)
	if rCtx.ReferrersProvider != nil {
		childrenHandler = images.SetReferrers(rCtx.ReferrersProvider, childrenHandler)
	}
	// Set any children labels for that content
	childrenHandler = images.SetChildrenMappedLabels(c.cs, childrenHandler, rCtx.ChildLabelMap)
	if rCtx.AllMetadata {
		// Filter manifests by platforms but allow to handle manifest
		// and configuration for not-target platforms
		childrenHandler = remotes.FilterManifestByPlatformHandler(childrenHandler, rCtx.PlatformMatcher)
	} else {
		// Filter children by platforms if specified.
		childrenHandler = images.FilterPlatforms(childrenHandler, c.platform)
	}

	// set isConvertible to true if there is application/octet-stream media type
	convertibleHandler := images.HandlerFunc(
		func(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			if desc.MediaType == docker.LegacyConfigMediaType {
				isConvertible = true
			}

			return []ocispec.Descriptor{}, nil
		},
	)

	appendDistSrcLabelHandler, err := docker.AppendDistributionSourceLabel(c.cs, ref)
	if err != nil {
		return images.Image{}, err
	}

	handlers := append(rCtx.BaseHandlers,
		remotes.FetchHandler(c.cs, fetcher),
		convertibleHandler,
		childrenHandler,
		appendDistSrcLabelHandler,
	)

	handler = images.Handlers(handlers...)

	converterFunc = func(ctx context.Context, desc ocispec.Descriptor) (ocispec.Descriptor, error) {
		return docker.ConvertManifest(ctx, c.cs, desc)
	}

	if rCtx.HandlerWrapper != nil {
		handler = rCtx.HandlerWrapper(handler)
	}

	if err := images.Dispatch(ctx, handler, limiter, desc); err != nil {
		return images.Image{}, err
	}

	if isConvertible {
		if desc, err = converterFunc(ctx, desc); err != nil {
			return images.Image{}, err
		}
	}

	img = images.Image{
		Name:   name,
		Target: desc,
		Labels: rCtx.Labels,
	}

	// Update/create the image in ImageStore
	for {
		if created, err := c.is.Create(ctx, img); err != nil {
			if !errdefs.IsAlreadyExists(err) {
				return img, err
			}

			updated, err := c.is.Update(ctx, img)
			if err != nil {
				// if image was removed, try create again
				if errdefs.IsNotFound(err) {
					continue
				}
				return img, err
			}
			img = updated
		} else {
			img = created
		}
		break
	}
	return img, nil
}
