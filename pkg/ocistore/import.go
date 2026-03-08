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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type importConfig struct {
	indexName       string
	imageRefT       func(string) string
	dgstRefT        func(digest.Digest) string
	skipDgstRef     func(string) bool
	allPlatforms    bool
	platformMatcher platforms.MatchComparer
	compress        bool
	discardLayers   bool
	skipMissing     bool
	imageLabels     map[string]string
	referrers       content.ReferrersProvider
}

type ImportOpts struct {
	cfg    importConfig
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

func WithImportApplyCommitOpts(opts ...ApplyCommitOpt) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.aOpts = append(iOpts.aOpts, opts...)
		return nil
	}
}

func WithImportIndexName(name string) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.indexName = name
		return nil
	}
}

func WithImportImageRefTranslator(f func(string) string) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.imageRefT = f
		return nil
	}
}

func WithImportDigestRef(f func(digest.Digest) string) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.dgstRefT = f
		return nil
	}
}

func WithImportSkipDigestRef(f func(string) bool) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.skipDgstRef = f
		return nil
	}
}

func WithImportAllPlatforms(all bool) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.allPlatforms = all
		return nil
	}
}

func WithImportPlatform(pm platforms.MatchComparer) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.platformMatcher = pm
		return nil
	}
}

func WithImportCompression() ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.compress = true
		return nil
	}
}

func WithImportDiscardLayers() ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.discardLayers = true
		return nil
	}
}

func WithImportSkipMissing() ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.skipMissing = true
		return nil
	}
}

func WithImportLabels(labels map[string]string) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.imageLabels = labels
		return nil
	}
}

func WithImportReferrers(r content.ReferrersProvider) ImportOpt {
	return func(iOpts *ImportOpts) error {
		iOpts.cfg.referrers = r
		return nil
	}
}

func (c *OCIStore) Import(reader io.Reader, opts ...ImportOpt) (_ []images.Image, retErr error) {
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
	iOpts := &ImportOpts{}
	for _, o := range opts {
		if err := o(iOpts); err != nil {
			return nil, err
		}
	}

	cfg := iOpts.cfg

	var aio []archive.ImportOpt
	if cfg.compress {
		aio = append(aio, archive.WithImportCompression())
	}

	index, err := archive.ImportIndex(ctx, c.cs, reader, aio...)
	if err != nil {
		return nil, err
	}

	var imgs []images.Image

	if cfg.indexName != "" {
		imgs = append(imgs, images.Image{
			Name:   cfg.indexName,
			Target: index,
		})
	}

	platformMatcher := c.platform
	if cfg.allPlatforms {
		platformMatcher = platforms.All
	} else if cfg.platformMatcher != nil {
		platformMatcher = cfg.platformMatcher
	}

	var handler images.HandlerFunc = func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.Digest != index.Digest {
			children, err := images.Children(ctx, c.cs, desc)
			if cfg.skipMissing && errdefs.IsNotFound(err) {
				return nil, images.ErrSkipDesc
			}
			return children, err
		}

		idx, err := importDecodeIndex(ctx, c.cs, desc)
		if err != nil {
			return nil, err
		}

		for _, m := range idx.Manifests {
			name := importImageName(m.Annotations, cfg.imageRefT)
			if name != "" {
				imgs = append(imgs, images.Image{
					Name:   name,
					Target: m,
				})
			}

			if _, ok := m.Annotations[images.AnnotationManifestSubject]; ok {
				continue
			}

			if cfg.skipDgstRef != nil && cfg.skipDgstRef(name) {
				continue
			}

			if cfg.dgstRefT != nil {
				ref := cfg.dgstRefT(m.Digest)
				if ref != "" {
					imgs = append(imgs, images.Image{
						Name:   ref,
						Target: m,
					})
				}
			}
		}

		return idx.Manifests, nil
	}

	handler = images.FilterPlatforms(handler, platformMatcher)
	if cfg.referrers != nil {
		handler = images.SetReferrers(cfg.referrers, handler)
	}
	if cfg.discardLayers {
		handler = images.SetChildrenMappedLabels(c.cs, handler, images.ChildGCLabelsFilterLayers)
	} else {
		handler = images.SetChildrenLabels(c.cs, handler)
	}

	if err := images.WalkNotEmpty(ctx, handler, index); err != nil {
		return nil, err
	}

	for i := range imgs {
		fieldsPath := []string{"target"}
		if cfg.imageLabels != nil {
			fieldsPath = append(fieldsPath, "labels")
			imgs[i].Labels = cfg.imageLabels
		}

		img, err := c.is.Update(ctx, imgs[i], fieldsPath...)
		if err != nil {
			if !errdefs.IsNotFound(err) {
				return nil, err
			}
			img, err = c.is.Create(ctx, imgs[i])
			if err != nil {
				return nil, err
			}
		}
		imgs[i] = img
	}

	if iOpts.unpack {
		var uErrs []error
		for i := range imgs {
			if err := c.unpack(ctx, &imgs[i], iOpts.aOpts...); err != nil {
				c.log.Errorf("failed to unpack image '%s': %v", imgs[i].Name, err)
				uErrs = append(uErrs, err)
			}
		}
		if len(uErrs) > 0 {
			return imgs, fmt.Errorf("failed unpacking some image")
		}
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

func importDecodeIndex(ctx context.Context, store content.Provider, desc ocispec.Descriptor) (*ocispec.Index, error) {
	var index ocispec.Index
	p, err := content.ReadBlob(ctx, store, desc)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(p, &index); err != nil {
		return nil, err
	}
	return &index, nil
}

func importImageName(annotations map[string]string, ociCleanup func(string) string) string {
	name := annotations[images.AnnotationImageName]
	if name != "" {
		return name
	}
	name = annotations[ocispec.AnnotationRefName]
	if name != "" && ociCleanup != nil {
		name = ociCleanup(name)
	}
	return name
}
