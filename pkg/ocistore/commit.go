/*
Copyright The containerd Authors
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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/rootfs"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The entire code of this file is porting the code from nerdctl imgutil/commit package

var (
	emptyGZLayer = digest.Digest("sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1")
	emptyDigest  = digest.Digest("")
)

type Changes struct {
	CMD, Entrypoint []string
}

type ImgOpts struct {
	Author  string
	Message string
	Ref     string
	Changes Changes
	Labels  map[string]string
}

type CommitImgOpts struct {
	ApplyCommitOpts
	iOpts ImgOpts
	dOpts []diff.Opt
}

type ApplyCommitOpts struct {
	sOpts []snapshots.Opt
	aOpts []diff.ApplyOpt
}

type CommitImgOpt func(*CommitImgOpts) error
type ApplyCommitOpt func(*ApplyCommitOpts) error

func WithSnapshotsOpts(opts ...snapshots.Opt) ApplyCommitOpt {
	return func(co *ApplyCommitOpts) error {
		co.sOpts = append(co.sOpts, opts...)
		return nil
	}
}

func WithApplyOpts(opts ...diff.ApplyOpt) ApplyCommitOpt {
	return func(co *ApplyCommitOpts) error {
		co.aOpts = append(co.aOpts, opts...)
		return nil
	}
}

func WithImgApplyCommitOpts(opts ...ApplyCommitOpt) CommitImgOpt {
	return func(co *CommitImgOpts) error {
		for _, o := range opts {
			err := o(&co.ApplyCommitOpts)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func WithImgCommitOpts(iOpts ImgOpts) CommitImgOpt {
	return func(co *CommitImgOpts) error {
		co.iOpts = iOpts
		return nil
	}
}

func (c *OCIStore) Commit(snapshotKey string, opts ...CommitImgOpt) (_ *images.Image, err error) {
	if !c.IsInitiated() {
		return nil, errors.New(missInitErrMsg)
	}

	cOpt := &CommitImgOpts{
		ApplyCommitOpts: ApplyCommitOpts{
			sOpts: []snapshots.Opt{},
			aOpts: []diff.ApplyOpt{},
		},
		dOpts: []diff.Opt{},
	}
	for _, o := range opts {
		err := o(cOpt)
		if err != nil {
			return nil, err
		}
	}

	sn := c.snaps[c.driver]

	// TODO which is the dirty data to clean?
	// Don't gc me and clean the dirty data after 1 hour!
	ctx, done, err := c.WithLease(leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("failed to create lease for commit: %w", err)
	}
	defer func() {
		e := done(ctx)
		if e != nil && err == nil {
			err = e
		}
	}()

	info, err := sn.Stat(ctx, snapshotKey)
	if err != nil {
		return nil, err
	}

	var baseImgConfig ocispec.Image
	var baseMfst *ocispec.Manifest

	if imgRef, ok := info.Labels[LabelSnapshotImgRef]; ok {
		baseImage, err := c.is.Get(ctx, imgRef)
		if err != nil {
			return nil, err
		}
		baseImgConfig, _, err = c.ReadImageConfig(ctx, baseImage)
		if err != nil {
			return nil, err
		}

		baseMfst, _, err = c.ReadManifest(ctx, baseImage)
		if err != nil {
			return nil, err
		}
	}

	// TODO ensure all content for baseImage

	diffLayerDesc, diffID, err := createDiff(ctx, snapshotKey, sn, c.cs, c.ds, cOpt.dOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to export layer: %w", err)
	}

	imageConfig, err := generateCommitImageConfig(baseImgConfig, diffID, &cOpt.iOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate commit image config: %w", err)
	}

	rootfsID := identity.ChainID(imageConfig.RootFS.DiffIDs).String()
	if err := applyDiffLayer(ctx, rootfsID, snapshotKey, sn, c.ds, diffLayerDesc); err != nil {
		return nil, fmt.Errorf("failed to apply diff: %w", err)
	}

	// TODO shall we keep the configDigest for something?
	commitManifestDesc, _, err := writeContentsForImage(ctx, c.cs, c.driver, baseMfst, imageConfig, diffLayerDesc)
	if err != nil {
		return nil, err
	}

	imgLabels := map[string]string{}
	if len(cOpt.iOpts.Labels) > 0 {
		imgLabels = cOpt.iOpts.Labels
	}

	// image create
	img := images.Image{
		Name:      cOpt.iOpts.Ref,
		Target:    commitManifestDesc,
		CreatedAt: time.Now(),
		Labels:    imgLabels,
	}

	if _, err := c.is.Update(ctx, img); err != nil {
		if !errdefs.IsNotFound(err) {
			return nil, err
		}

		if _, err := c.is.Create(ctx, img); err != nil {
			return nil, fmt.Errorf("failed to create new image %s: %w", cOpt.iOpts.Ref, err)
		}
	}

	// unpack the image to snapshotter
	if err := c.unpack(ctx, &img); err != nil {
		return nil, err
	}

	c.log.Infof("Successfully committed image '%s'", img.Name)
	// TODO should we run a snapshotter cleanup at this point?
	return &img, nil
}

// createDiff creates a layer diff into containerd's content store.
func createDiff(ctx context.Context, name string, sn snapshots.Snapshotter, cs content.Store, comparer diff.Comparer, dOpts ...diff.Opt) (ocispec.Descriptor, digest.Digest, error) {
	newDesc, err := rootfs.CreateDiff(ctx, name, sn, comparer, dOpts...)
	if err != nil {
		return ocispec.Descriptor{}, digest.Digest(""), err
	}

	info, err := cs.Info(ctx, newDesc.Digest)
	if err != nil {
		return ocispec.Descriptor{}, digest.Digest(""), err
	}

	diffIDStr, ok := info.Labels["containerd.io/uncompressed"]
	if !ok {
		return ocispec.Descriptor{}, digest.Digest(""), fmt.Errorf("invalid differ response with no diffID")
	}

	diffID, err := digest.Parse(diffIDStr)
	if err != nil {
		return ocispec.Descriptor{}, digest.Digest(""), err
	}

	return ocispec.Descriptor{
		MediaType: images.MediaTypeDockerSchema2LayerGzip,
		Digest:    newDesc.Digest,
		Size:      info.Size,
	}, diffID, nil
}

// generateCommitImageConfig returns commit oci image config based on the container's image.
func generateCommitImageConfig(baseConfig ocispec.Image, diffID digest.Digest, opts *ImgOpts) (ocispec.Image, error) {
	// TODO(fuweid): support updating the USER/ENV/... fields?
	if opts.Changes.CMD != nil {
		baseConfig.Config.Cmd = opts.Changes.CMD
	}
	if opts.Changes.Entrypoint != nil {
		baseConfig.Config.Entrypoint = opts.Changes.Entrypoint
	}
	if opts.Author == "" {
		opts.Author = baseConfig.Author
	}

	createdBy := ""
	createdTime := time.Now()
	arch := baseConfig.Architecture
	if arch == "" {
		arch = runtime.GOARCH
		//TODO log warning assuming ARCH
	}
	os := baseConfig.OS
	if os == "" {
		os = runtime.GOOS
		// TODO log warning assuming OS
	}

	return ocispec.Image{
		Platform: ocispec.Platform{
			Architecture: arch,
			OS:           os,
		},

		Created: &createdTime,
		Author:  opts.Author,
		Config:  baseConfig.Config,
		RootFS: ocispec.RootFS{
			Type:    "layers",
			DiffIDs: append(baseConfig.RootFS.DiffIDs, diffID),
		},
		History: append(baseConfig.History, ocispec.History{
			Created:    &createdTime,
			CreatedBy:  createdBy,
			Author:     opts.Author,
			Comment:    opts.Message,
			EmptyLayer: (diffID == emptyGZLayer),
		}),
	}, nil
}

// writeContentsForImage will commit oci image config and manifest into containerd's content store.
func writeContentsForImage(ctx context.Context, cs content.Store, snName string, baseMfst *ocispec.Manifest, newConfig ocispec.Image, diffLayerDesc ocispec.Descriptor) (ocispec.Descriptor, digest.Digest, error) {
	newConfigJSON, err := json.Marshal(newConfig)
	if err != nil {
		return ocispec.Descriptor{}, emptyDigest, err
	}

	configDesc := ocispec.Descriptor{
		MediaType: images.MediaTypeDockerSchema2Config,
		Digest:    digest.FromBytes(newConfigJSON),
		Size:      int64(len(newConfigJSON)),
	}

	layers := []ocispec.Descriptor{diffLayerDesc}
	if baseMfst != nil {
		layers = append(baseMfst.Layers, layers...)
	}

	newMfst := struct {
		MediaType string `json:"mediaType,omitempty"`
		ocispec.Manifest
	}{
		MediaType: images.MediaTypeDockerSchema2Manifest,
		Manifest: ocispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: configDesc,
			Layers: layers,
		},
	}

	newMfstJSON, err := json.MarshalIndent(newMfst, "", "    ")
	if err != nil {
		return ocispec.Descriptor{}, emptyDigest, err
	}

	newMfstDesc := ocispec.Descriptor{
		MediaType: images.MediaTypeDockerSchema2Manifest,
		Digest:    digest.FromBytes(newMfstJSON),
		Size:      int64(len(newMfstJSON)),
	}

	// new manifest should reference the layers and config content
	labels := map[string]string{
		"containerd.io/gc.ref.content.0": configDesc.Digest.String(),
	}
	for i, l := range layers {
		labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i+1)] = l.Digest.String()
	}

	err = content.WriteBlob(ctx, cs, newMfstDesc.Digest.String(), bytes.NewReader(newMfstJSON), newMfstDesc, content.WithLabels(labels))
	if err != nil {
		return ocispec.Descriptor{}, emptyDigest, err
	}

	// config should reference to snapshotter
	labelOpt := content.WithLabels(map[string]string{
		fmt.Sprintf("containerd.io/gc.ref.snapshot.%s", snName): identity.ChainID(newConfig.RootFS.DiffIDs).String(),
	})
	err = content.WriteBlob(ctx, cs, configDesc.Digest.String(), bytes.NewReader(newConfigJSON), configDesc, labelOpt)
	if err != nil {
		return ocispec.Descriptor{}, emptyDigest, err
	}

	return newMfstDesc, configDesc.Digest, nil
}

// applyDiffLayer will apply diff layer content created by createDiff into the snapshotter.
func applyDiffLayer(ctx context.Context, name string, snapshotKey string, sn snapshots.Snapshotter, differ diff.Applier, diffDesc ocispec.Descriptor) (retErr error) {
	mounts, err := sn.Mounts(ctx, snapshotKey)
	if err != nil {
		return err
	}

	if _, err = differ.Apply(ctx, diffDesc, mounts); err != nil {
		return err
	}

	// Label added here is just to be consistent with unpacked images, I don't know the motivation of this label
	if err = sn.Commit(ctx, name, snapshotKey, snapshots.WithLabels(map[string]string{
		"containerd.io/snapshot.ref": name,
	})); err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}
