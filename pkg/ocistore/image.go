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

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/image-spec/identity"
)

func (c *OCIStore) Get(ctx context.Context, ref string) (*images.Image, error) {
	if !c.IsInitiated() {
		return nil, errors.New(missInitErrMsg)
	}

	c.log.Debugf("Looking for image %q in image store", ref)
	img, err := c.is.Get(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("getting image '%s' from store: %w", ref, err)
	}
	c.log.Infof("Image %q found", ref)
	return &img, nil
}

func (c *OCIStore) isUnpacked(ctx context.Context, img *images.Image) (bool, error) {
	if !c.IsInitiated() {
		return false, errors.New(missInitErrMsg)
	}
	if img == nil {
		return false, fmt.Errorf("nil image")
	}
	diffIDs, err := img.RootFS(ctx, c.cs, c.platform)
	if err != nil {
		return false, fmt.Errorf("getting image rootfs: %w", err)
	}
	_, err = c.snaps[c.driver].Stat(ctx, identity.ChainID(diffIDs).String())
	if errdefs.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("looking for image %q in snapshotter: %w", img.Name, err)
	}
	return true, nil
}

func (c *OCIStore) List(filters ...string) ([]images.Image, error) {
	if !c.IsInitiated() {
		return nil, errors.New(missInitErrMsg)
	}

	return c.is.List(c.ctx, filters...)
}

func (c *OCIStore) Delete(name string, opts ...images.DeleteOpt) (retErr error) {
	if !c.IsInitiated() {
		return errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to delete image: %v", err)
		return err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on delete image operation")
		}
	}()

	err = c.delete(ctx, name, opts...)
	if err != nil {
		c.log.Errorf("failed deleting image '%s': %v", name, err)
		return err
	}

	c.log.Infof("Successfully deleted image '%s'", name)
	return nil
}

func (c *OCIStore) Update(img images.Image, fieldpaths ...string) (i images.Image, retErr error) {
	if !c.IsInitiated() {
		return i, errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to update image: %v", err)
		return i, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on update image operation")
		}
	}()

	return c.is.Update(ctx, img, fieldpaths...)
}

func (c *OCIStore) Create(img images.Image) (i images.Image, retErr error) {
	if !c.IsInitiated() {
		return i, errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to create image: %v", err)
		return i, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on create image operation")
		}
	}()

	return c.is.Create(ctx, img)
}

func (c *OCIStore) delete(ctx context.Context, name string, opts ...images.DeleteOpt) error {
	img, err := c.Get(ctx, name)
	if err != nil {
		return err
	}
	if ok, err := c.isUnpacked(ctx, img); ok {
		diffIDs, err := img.RootFS(ctx, c.cs, c.platform)
		if err != nil {
			return err
		}
		chainID := identity.ChainID(diffIDs).String()
		err = c.removeSnapshotsChain(ctx, c.GetSnapshotter(c.GetDriver()), chainID, -1)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	return c.is.Delete(ctx, name, opts...)
}
