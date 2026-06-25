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
	"io"
	"os"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
)

type ImportOpts struct {
	iOpts  []client.ImportOpt
	aOpts  []ApplyCommitOpt
	unpack bool
}

type ImportOpt func(*ImportOpts) error

func WithImportUnpack() ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.unpack = true
		return nil
	}
}

func WithImportOpts(opts ...client.ImportOpt) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.iOpts = append(iOpts.iOpts, opts...)
		return nil
	}
}

func WithImportApplyCommitOpts(opts ...ApplyCommitOpt) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.aOpts = append(iOpts.aOpts, opts...)
		return nil
	}
}

func (c *OCIStore) Import(reader io.Reader, opts ...ImportOpt) (_ []images.Image, retErr error) {
	if !c.IsInitiated() {
		return nil, errors.New(missInitErrMsg)
	}

	ctx, done, err := c.cli.WithLease(c.ctx, leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to import image: %v", err)
		return nil, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on import operation")
		}
	}()

	imgs, err := c.importFunc(ctx, reader, opts...)
	if err != nil {
		c.log.Error("failed importing from reader interface")
	}

	c.log.Infof("Successfully imported %d image(s)", len(imgs))
	return imgs, nil
}

func (c *OCIStore) ImportFile(file string, opts ...ImportOpt) (_ []images.Image, retErr error) {
	if !c.IsInitiated() {
		return nil, errors.New(missInitErrMsg)
	}

	ctx, done, err := c.cli.WithLease(c.ctx, leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to import image: %v", err)
		return nil, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on import operation")
		}
	}()

	imgs, err := c.importFile(ctx, file, opts...)
	if err != nil {
		c.log.Errorf("failed importing from file '%s'", file)
	}

	c.log.Infof("Successfully imported %d image(s) from '%s'", len(imgs), file)

	return imgs, nil
}

func (c *OCIStore) SingleImportFile(file string, opts ...ImportOpt) (_ *images.Image, retErr error) {
	if !c.IsInitiated() {
		return nil, errors.New(missInitErrMsg)
	}

	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease to import image: %v", err)
		return nil, err
	}
	defer func() {
		err = done(ctx)
		if err != nil && retErr == nil {
			c.log.Warnf("could not remove lease on import operation")
		}
	}()

	imgs, err := c.importFile(ctx, file, opts...)
	if err != nil {
		c.log.Errorf("failed importing from file '%s'", file)
	}

	if len(imgs) == 0 {
		c.log.Errorf("no images imported from file '%s'", file)
		return nil, fmt.Errorf("something went wrong, no images imported")
	}

	if len(imgs) > 1 {
		var dErrs []error
		delImg := func(img images.Image) {
			err = c.delete(ctx, img.Name)
			if err != nil {
				c.log.Errorf("cound not delete imported image '%s': %v", img.Name, err)
				dErrs = append(dErrs, err)
			}
		}

		c.log.Warnf("imported '%d' images. Only keeping first one", len(imgs))
		for _, img := range imgs[1:] {
			delImg(img)
		}
		if len(dErrs) > 0 {
			delImg(imgs[0])
			return nil, fmt.Errorf("failed removing imported images")
		}
	}
	c.log.Infof("Successfully imported '%s' image from '%s'", imgs[0].Name, file)
	return &imgs[0], nil
}

func (c *OCIStore) importFunc(ctx context.Context, reader io.Reader, opts ...ImportOpt) ([]images.Image, error) {
	// TODO add unpack option
	iOpts := &ImportOpts{
		iOpts: []client.ImportOpt{},
		aOpts: []ApplyCommitOpt{},
	}
	for _, o := range opts {
		err := o(iOpts)
		if err != nil {
			return nil, err
		}
	}

	imgs := []images.Image{}
	imgs, err := c.cli.Import(ctx, reader, iOpts.iOpts...)
	if err != nil {
		return nil, err
	}
	var uErrs []error
	for _, img := range imgs {
		imgs = append(imgs, img)
		if iOpts.unpack {
			err = c.unpack(ctx, &img, iOpts.aOpts...)
			if err != nil {
				c.log.Errorf("failed to unpack image '%s': %v", img.Name, err)
				uErrs = append(uErrs, err)
			}
		}
	}
	if len(uErrs) > 0 {
		return imgs, fmt.Errorf("failed unpacking some image")
	}

	return imgs, nil
}

func (c *OCIStore) importFile(ctx context.Context, file string, opts ...ImportOpt) (_ []images.Image, retErr error) {
	r, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := r.Close()
		if err != nil && retErr == nil {
			retErr = err
		}
	}()

	return c.importFunc(ctx, r, opts...)
}
