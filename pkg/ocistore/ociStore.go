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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/metadata"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/containerd/v2/plugins/snapshots/overlay"
	"github.com/containerd/platforms"
	"github.com/davidcassany/ocistore/pkg/logger"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
)

const (
	overlayDriver = "overlayfs"
	snapshotsDir  = "snapshots"
	boltDbFile    = "metadata.db"
	contentDir    = "content"
	namespace     = "elemental-system"

	DefaultRoot         = "/tmp/contentstore"
	LabelSnapshotImgRef = "containerd.io/snapshot/image.ref"

	missInitErrMsg = "uninitiated containerdstore instance"

	// TopLevelBucket isolates our custom data from containerd's bucket
	// we don't want to mess with containerd's DB and potentially corrupt it or break
	// containerd updates
	TopLevelBucket = "zstd-cache"
	LocBucket      = "digest-locations"
	SnapshotBucket = "snapshot-digests"
)

type OCIStore struct {
	log  logger.Logger
	root string

	// TODO create options to provide those
	driver    string
	namespace string
	platform  platforms.MatchComparer

	ctx   context.Context
	db    *metadata.DB
	bdb   *bolt.DB
	lm    leases.Manager
	is    images.Store
	cs    content.Store
	ds    client.DiffService
	snaps map[string]snapshots.Snapshotter
	cli   *client.Client
}

func NewOCIStore(log logger.Logger, root string) *OCIStore {
	return &OCIStore{
		root: root, driver: overlayDriver, namespace: namespace,
		log: log, platform: platforms.DefaultStrict(),
	}
}

func (c OCIStore) Logger() logger.Logger {
	return c.log
}

func (c *OCIStore) Init(mainCtx context.Context) error {
	var err error
	snapshotters := map[string]snapshots.Snapshotter{}

	ctx := namespaces.WithNamespace(mainCtx, "testing")

	switch c.driver {
	case overlayDriver:
		//TODO make overlay opts configurable
		sn, err := overlay.NewSnapshotter(filepath.Join(c.root, snapshotsDir))
		if err != nil {
			return err
		}
		snapshotters[overlayDriver] = sn
	default:
		return fmt.Errorf("unsupported containerd driver '%s'", c.driver)
	}

	bdb, err := bolt.Open(filepath.Join(c.root, boltDbFile), 0644, nil)
	if err != nil {
		return err
	}

	store, err := local.NewStore(filepath.Join(c.root, contentDir))
	if err != nil {
		return err
	}

	db := metadata.NewDB(bdb, store, snapshotters)
	err = db.Init(ctx)
	if err != nil {
		return err
	}

	lm := metadata.NewLeaseManager(db)
	is := metadata.NewImageStore(db)
	cs := db.ContentStore()
	ds := NewDiffService(cs)

	// TODO make client opts configurable
	cli, err := client.NewWithConn(nil, client.WithServices(
		client.WithContentStore(cs),
		client.WithImageStore(is),
		client.WithLeasesService(lm),
		client.WithDiffService(ds),
		client.WithSnapshotters(snapshotters),
	), client.WithDefaultPlatform(c.platform))
	if err != nil {
		return err
	}

	// Init our zstd:chunked cache database
	err = initZstdCacheBuckets(bdb)
	if err != nil {
		return err
	}

	c.ctx = ctx
	c.db = db
	c.cli = cli
	c.bdb = bdb
	c.lm = lm
	c.is = is
	c.cs = cs
	c.ds = ds
	c.snaps = snapshotters
	return nil
}

func (c *OCIStore) IsInitiated() bool {
	return c.ctx != nil
}

func (c *OCIStore) Ctx() context.Context {
	return c.ctx
}

func (c *OCIStore) RunGarbageCollector() error {
	gcStats, err := c.db.GarbageCollect(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to run garbage collection: %w", err)
	}

	c.log.Debugf("Garbage Collection complete. Elapsed time: %v\n", gcStats.Elapsed())
	return nil
}

// WithLease attaches a lease on the OCIStore context
func (c *OCIStore) WithLease(opts ...leases.Opt) (context.Context, func(context.Context) error, error) {
	nop := func(context.Context) error { return nil }

	_, ok := leases.FromContext(c.ctx)
	if ok {
		return c.ctx, nop, nil
	}

	if len(opts) == 0 {
		// Use default lease configuration if no options provided
		opts = []leases.Opt{
			leases.WithRandomID(),
			leases.WithExpiration(24 * time.Hour),
		}
	}

	l, err := c.lm.Create(c.ctx, opts...)
	if err != nil {
		return c.ctx, nop, err
	}

	ctx := leases.WithLease(c.ctx, l.ID)
	return ctx, func(ctx context.Context) error {
		return c.lm.Delete(ctx, l)
	}, nil
}

func (c *OCIStore) GetClient() *client.Client {
	if !c.IsInitiated() {
		return nil
	}
	return c.cli
}

func (c *OCIStore) GetDriver() string {
	if !c.IsInitiated() {
		return ""
	}
	return c.driver
}

// Methods copied from nerdctl imgutils package, adding a dependency to nerdctl could be considered

// ReadImageConfig reads the config spec (`application/vnd.oci.image.config.v1+json`) for img.platform from content store.
func ReadImageConfig(ctx context.Context, img client.Image) (ocispec.Image, ocispec.Descriptor, error) {
	var config ocispec.Image

	configDesc, err := img.Config(ctx) // aware of img.platform
	if err != nil {
		return config, configDesc, err
	}
	p, err := content.ReadBlob(ctx, img.ContentStore(), configDesc)
	if err != nil {
		return config, configDesc, err
	}
	if err := json.Unmarshal(p, &config); err != nil {
		return config, configDesc, err
	}
	return config, configDesc, nil
}

// ReadIndex returns image index, or nil for non-indexed image.
func ReadIndex(ctx context.Context, img client.Image) (*ocispec.Index, *ocispec.Descriptor, error) {
	desc := img.Target()
	if !images.IsIndexType(desc.MediaType) {
		return nil, nil, nil
	}
	b, err := content.ReadBlob(ctx, img.ContentStore(), desc)
	if err != nil {
		return nil, &desc, err
	}
	var idx ocispec.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, &desc, err
	}

	return &idx, &desc, nil
}

func initZstdCacheBuckets(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		// 1. Create our isolated top-level root bucket
		root, err := tx.CreateBucketIfNotExists([]byte(TopLevelBucket))
		if err != nil {
			return fmt.Errorf("failed to create root cache bucket: %w", err)
		}

		// 2. Create the Forward Index (Chunk Digest -> Paths)
		if _, err := root.CreateBucketIfNotExists([]byte(LocBucket)); err != nil {
			return fmt.Errorf("failed to create chunk locations bucket: %w", err)
		}

		// 3. Create the Reverse Index (Snapshot ID -> Chunk Digests)
		if _, err := root.CreateBucketIfNotExists([]byte(SnapshotBucket)); err != nil {
			return fmt.Errorf("failed to create snapshot chunks bucket: %w", err)
		}

		return nil
	})
}

// ReadManifest returns the manifest for img.platform, or nil if no manifest was found.
func ReadManifest(ctx context.Context, img client.Image) (*ocispec.Manifest, *ocispec.Descriptor, error) {
	cs := img.ContentStore()
	targetDesc := img.Target()
	if images.IsManifestType(targetDesc.MediaType) {
		b, err := content.ReadBlob(ctx, img.ContentStore(), targetDesc)
		if err != nil {
			return nil, &targetDesc, err
		}
		var mani ocispec.Manifest
		if err := json.Unmarshal(b, &mani); err != nil {
			return nil, &targetDesc, err
		}
		return &mani, &targetDesc, nil
	}
	if images.IsIndexType(targetDesc.MediaType) {
		idx, _, err := ReadIndex(ctx, img)
		if err != nil {
			return nil, nil, err
		}
		configDesc, err := img.Config(ctx) // aware of img.platform
		if err != nil {
			return nil, nil, err
		}
		// We can't access the private `img.platform` variable.
		// So, we find the manifest object by comparing the config desc.
		for _, maniDesc := range idx.Manifests {
			maniDesc := maniDesc
			// ignore non-nil err
			if b, err := content.ReadBlob(ctx, cs, maniDesc); err == nil {
				var mani ocispec.Manifest
				if err := json.Unmarshal(b, &mani); err != nil {
					return nil, nil, err
				}
				if reflect.DeepEqual(configDesc, mani.Config) {
					return &mani, &maniDesc, nil
				}
			}
		}
	}
	// no manifest was found
	return nil, nil, nil
}

// copied from github.com/containerd/containerd/rootfs/apply.go
func uniquePart() string {
	t := time.Now()
	var b [3]byte
	// Ignore read failures, just decreases uniqueness
	rand.Read(b[:])
	return fmt.Sprintf("%d-%s", t.Nanosecond(), base64.URLEncoding.EncodeToString(b[:]))
}
