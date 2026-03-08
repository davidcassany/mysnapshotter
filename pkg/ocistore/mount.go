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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/image-spec/identity"
)

type MountOpts struct {
	sOpts  []snapshots.Opt
	aOpts  []ApplyCommitOpt
	unpack bool
}

type MountOpt func(*MountOpts) error

func WithMountUnpack() MountOpt {
	return func(mOpts *MountOpts) error {
		mOpts.unpack = true
		return nil
	}
}

func WithMountSnapshotOpts(opts ...snapshots.Opt) MountOpt {
	return func(mOpts *MountOpts) error {
		mOpts.sOpts = append(mOpts.sOpts, opts...)
		return nil
	}
}

func WithMountApplyCommitOpts(opts ...ApplyCommitOpt) MountOpt {
	return func(mOpts *MountOpts) error {
		mOpts.aOpts = append(mOpts.aOpts, opts...)
		return nil
	}
}

func (c *OCIStore) MountFromScratch(target string, key string) (string, error) {
	return c.Mount(nil, target, key, false)
}

func (c *OCIStore) Mount(img *images.Image, target string, key string, readonly bool, opts ...MountOpt) (snapshotKey string, retErr error) {
	if !c.IsInitiated() {
		return "", errors.New(missInitErrMsg)
	}

	mOpt := &MountOpts{
		aOpts: []ApplyCommitOpt{},
		sOpts: []snapshots.Opt{},
	}
	for _, o := range opts {
		err := o(mOpt)
		if err != nil {
			return "", err
		}
	}

	if key == "" {
		// TODO there is probably a better scheme, is target needed at all?
		key = uniquePart() + "-" + strings.ReplaceAll(strings.Trim(target, "/"), "/", "-")
	}

	// TODO handle lease properly, whats the purpose of this setup?
	ctx, done, err := c.WithLease(
		leases.WithID(key),
		leases.WithExpiration(1*time.Hour),
		leases.WithLabel("containerd.io/gc.ref.snapshot."+c.driver, key),
	)
	if err != nil && !errdefs.IsAlreadyExists(err) {
		return "", err
	}

	defer func() {
		if retErr != nil && done != nil {
			done(ctx)
		}
	}()

	// TODO create and/or check target existence?

	if mOpt.unpack {
		err = c.unpack(ctx, img, mOpt.aOpts...)
		if err != nil {
			c.log.Errorf("failed to unpack image '%s': %v", img.Name, err)
			return "", err
		}
		c.log.Infof("Successfully unpacked image '%s'", img.Name)
	}

	var parent string
	labels := map[string]string{
		"containerd.io/gc.root": time.Now().UTC().Format(time.RFC3339),
	}

	// TODO properly name labels
	if img == nil {
		parent = ""
	} else {
		diffIDs, err := img.RootFS(ctx, c.cs, c.platform)
		if err != nil {
			c.log.Errorf("failed to get diff IDs of the image '%s': %v", img.Name, err)
			return "", err
		}
		parent = identity.ChainID(diffIDs).String()
		labels = map[string]string{
			LabelSnapshotImgRef: img.Name,
		}
	}

	sn := c.snaps[c.driver]

	sOpts := append(mOpt.sOpts, snapshots.WithLabels(labels))

	var mounts []mount.Mount
	if readonly {
		mounts, err = sn.View(ctx, key, parent, sOpts...)
	} else {
		mounts, err = sn.Prepare(ctx, key, parent, sOpts...)
	}

	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			mounts, err = sn.Mounts(ctx, key)
		}
		if err != nil {
			c.log.Errorf("failed to create an active commit for image '%s': %v", img.Name, err)
			return "", err
		}
	}

	if err := mount.All(mounts, target); err != nil {
		if err := sn.Remove(ctx, key); err != nil && !errdefs.IsNotFound(err) {
			c.log.Errorf("error cleaning up snapshot after mount error: %v", err)
		}
		c.log.Errorf("failed to mount image '%s': %v", img.Name, err)
		return "", err
	}

	return key, nil
}

func (c *OCIStore) Umount(target string, key string, removeSnap int) (retErr error) {
	if !c.IsInitiated() {
		return errors.New(missInitErrMsg)
	}

	if err := mount.UnmountAll(target, 0); err != nil {
		return err
	}

	// Do not remove any snapshot
	if removeSnap == 0 {
		return nil
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to umount snapshot: %v", err)
		return err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on umount snapshot operation")
		}
	}()

	if err := c.lm.Delete(ctx, leases.Lease{ID: key}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("error deleting lease: %w", err)
	}
	s := c.snaps[c.driver]

	// TODO should we run a snapshotter cleanup after snapshots removal?
	// Remove up to a certain level of childs
	if removeSnap > 0 {
		return c.removeSnapshotsChain(ctx, s, key, removeSnap-1)
	}

	// Remove the entire chain
	return c.removeSnapshotsChain(ctx, s, key, -1)
}
