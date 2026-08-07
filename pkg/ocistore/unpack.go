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

	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/unpack"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func (c *OCIStore) Unpack(ref string, opts ...ApplyCommitOpt) (err error) {
	if !c.IsInitiated() {
		return errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		return fmt.Errorf("creating lease to unpack '%s': %w", ref, err)
	}
	defer func() {
		e := done(ctx)
		if err == nil && e != nil {
			err = e
		}
	}()

	img, err := c.Get(ctx, ref)
	if err != nil {
		return fmt.Errorf("image not found: %w", err)
	}

	unpacked, err := c.isUnpacked(ctx, img)
	if err != nil {
		return fmt.Errorf("checking %q: %w", ref, err)
	}

	if !unpacked {
		return c.unpack(ctx, img, opts...)
	}

	c.log.Infof("Image %q already unpacked, nothing to do", ref)
	return nil
}

func (c *OCIStore) unpack(ctx context.Context, img *images.Image, opts ...ApplyCommitOpt) error {
	cOpt := &ApplyCommitOpts{
		sOpts: []snapshots.Opt{},
		aOpts: []diff.ApplyOpt{},
	}
	for _, o := range opts {
		err := o(cOpt)
		if err != nil {
			return err
		}
	}

	uPlat := unpack.Platform{
		Platform:       c.platform,
		SnapshotterKey: c.driver,
		Snapshotter:    c.snaps[c.driver],
		SnapshotOpts:   cOpt.sOpts,
		Applier:        c.ds,
		ApplyOpts:      cOpt.aOpts,
	}
	unpacker, err := unpack.NewUnpacker(ctx, c.cs, unpack.WithUnpackPlatform(uPlat))
	if err != nil {
		return err
	}

	desc := img.Target

	var handlerFunc images.HandlerFunc = func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return images.Children(ctx, c.cs, desc)
	}
	var handler images.Handler
	handler = images.Handlers(images.FilterPlatforms(handlerFunc, c.platform))

	handler = unpacker.Unpack(handler)

	if err := images.WalkNotEmpty(ctx, handler, desc); err != nil {
		if unpacker != nil {
			// wait for unpacker to cleanup
			unpacker.Wait()
		}
		if errors.Is(images.ErrEmptyWalk, err) {
			c.log.Warnf("there are no children to unpack")
			return nil
		}

		return fmt.Errorf("walking %q image descriptors: %w", img.Name, err)
	}

	if unpacker != nil {
		if _, err = unpacker.Wait(); err != nil {
			return fmt.Errorf("unpacking image %q: %w", img.Name, err)
		}
	}

	return nil
}
