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
	"maps"
	"time"

	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
)

func (c *OCIStore) ListSnapshots(filters ...string) (_ []snapshots.Info, retErr error) {
	if !c.IsInitiated() {
		return nil, errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to list snapshots: %v", err)
		return nil, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on list snapshots operation")
		}
	}()

	sn := c.GetSnapshotter(c.GetDriver())

	infos, err := listSnapshots(ctx, sn, filters...)
	if err != nil && errdefs.IsNotFound(err) {
		c.log.Warnf("returned a IsNotFound error, this is likely to mean no snapshot has been ever created yet in current content store")
		return infos, nil
	}

	return infos, err
}

func (c *OCIStore) GetSnapshot(key string) (_ snapshots.Info, retErr error) {
	var info snapshots.Info
	if !c.IsInitiated() {
		return info, errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to get snapshot: %v", err)
		return info, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on get snapshot operation")
		}
	}()

	sn := c.GetSnapshotter(c.GetDriver())
	return sn.Stat(c.ctx, key)
}

func (c *OCIStore) UpdateSnapshot(info snapshots.Info, fieldpaths ...string) (_ snapshots.Info, retErr error) {
	if !c.IsInitiated() {
		return info, errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to update snapshot: %v", err)
		return info, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on update snapshot operation")
		}
	}()

	info, err = c.updateSnapshot(c.ctx, info, fieldpaths...)
	if err != nil {
		c.log.Errorf("failed to update snapshot '%s': %v", info.Name, err)
		return info, err
	}

	c.log.Infof("Successfully updated snapshot '%s'", info.Name)
	return info, nil
}

func (c *OCIStore) LabelSnapshot(name string, labels map[string]string) (retErr error) {
	if !c.IsInitiated() {
		return errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to get snapshot: %v", err)
		return err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on get snapshot operation")
		}
	}()

	sn := c.GetSnapshotter(c.GetDriver())
	info, err := sn.Stat(ctx, name)
	if err != nil {
		return err
	}

	_, err = c.labelSnapshot(ctx, info, labels)
	if err != nil {
		c.log.Errorf("failed to update snapshot '%s': %v", info.Name, err)
		return err
	}

	c.log.Infof("Successfully updated snapshot '%s'", info.Name)
	return nil
}

func (c *OCIStore) RemoveSnapshotLabels(name string, labelKeys ...string) (retErr error) {
	if !c.IsInitiated() {
		return errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to get snapshot: %v", err)
		return err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on get snapshot operation")
		}
	}()

	sn := c.GetSnapshotter(c.GetDriver())
	info, err := sn.Stat(ctx, name)
	if err != nil {
		return err
	}

	_, err = c.removeSnapshotLabels(ctx, info, labelKeys...)
	if err != nil {
		c.log.Errorf("failed to update snapshot '%s': %v", info.Name, err)
		return err
	}

	c.log.Infof("Successfully updated snapshot '%s'", info.Name)
	return nil
}

func listSnapshots(ctx context.Context, sn snapshots.Snapshotter, filters ...string) ([]snapshots.Info, error) {
	var snaps []snapshots.Info
	walkFunc := func(ctx context.Context, info snapshots.Info) error {
		snaps = append(snaps, info)
		return nil
	}

	err := sn.Walk(ctx, walkFunc, filters...)
	if err != nil {
		return nil, err
	}

	return snaps, nil
}

func (c *OCIStore) removeSnapshotsChain(ctx context.Context, s snapshots.Snapshotter, key string, depth int) error {
	var walkFunc func(ctx context.Context, s snapshots.Snapshotter, key string, step int) error

	walkFunc = func(ctx context.Context, s snapshots.Snapshotter, key string, step int) error {
		c.log.Debugf("removing snapshots chain step %d", step)
		sInfo, err := s.Stat(ctx, key)
		if err != nil {
			if errdefs.IsNotFound(err) {
				c.log.Warnf("stopped walking chain, snapshot '%s' not found", key)
				return nil
			}
			return err
		}
		if err := s.Remove(ctx, key); err != nil {
			// We can't remove snapshots having childs, attempting so returns a failed precondition
			if errdefs.IsFailedPrecondition(err) {
				return nil
			}
			return fmt.Errorf("error removing snapshot: %w", err)
		}
		if sInfo.Parent == "" || depth == 0 {
			return nil
		} else if depth > 0 {
			depth--
		}
		return walkFunc(ctx, s, sInfo.Parent, step+1)
	}
	return walkFunc(ctx, s, key, 0)
}

func (c *OCIStore) updateSnapshot(ctx context.Context, info snapshots.Info, fieldpaths ...string) (snapshots.Info, error) {
	sn := c.GetSnapshotter(c.GetDriver())
	return sn.Update(ctx, info, fieldpaths...)
}

func (c *OCIStore) removeSnapshotLabels(ctx context.Context, info snapshots.Info, labelKeys ...string) (snapshots.Info, error) {
	sLabels := info.Labels
	if sLabels == nil {
		sLabels = map[string]string{}
	}
	for _, k := range labelKeys {
		delete(sLabels, k)
	}
	info.Labels = sLabels

	return c.updateSnapshot(ctx, info)
}

func (c *OCIStore) labelSnapshot(ctx context.Context, info snapshots.Info, labels map[string]string) (snapshots.Info, error) {
	if info.Labels == nil {
		info.Labels = map[string]string{}
	}
	maps.Copy(info.Labels, labels)
	return c.updateSnapshot(ctx, info)
}
