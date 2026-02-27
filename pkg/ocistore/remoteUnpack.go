/*
Copyright © 2024-2026 SUSE LLC

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
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/containerd/stargz-snapshotter/estargz"
	"github.com/containerd/stargz-snapshotter/estargz/zstdchunked"
	"github.com/davidcassany/ocistore/pkg/logger"
	"github.com/klauspost/compress/zstd"
	"github.com/moby/sys/userns"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

func (c *OCIStore) RemoteUnpack(ref string, opts ...ApplyCommitOpt) (err error) {
	if !c.IsInitiated() {
		return errors.New(missInitErrMsg)
	}

	ctx, done, err := c.cli.WithLease(c.ctx, leases.WithRandomID(), leases.WithExpiration(1*time.Hour))
	if err != nil {
		c.log.Errorf("failed to create lease for unpacking '%s': %v", ref, err)
		return err
	}
	defer func() {
		dErr := done(ctx)
		if dErr != nil && err == nil {
			c.log.Warnf("could not remove lease for unpack operation")
		}
	}()

	// TODO verify it handles authorization
	resolver := setupResolver()

	name, desc, err := resolver.Resolve(c.ctx, ref)
	if err != nil {
		c.log.Errorf("failed resolving image reference into a name and OCI descriptor: %v", err)
		return err
	}

	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return fmt.Errorf("initiating fetcher for image %s: %w", name, err)
	}
	platformMatcher := platforms.DefaultStrict()

	// 2. Create a handler that ONLY fetches metadata (Manifests and Configs)
	// and entirely ignores layer blobs.
	handler := images.Handlers(
		images.FilterPlatforms(
			images.SetChildrenLabels(
				c.cli.ContentStore(), remoteChildren(c.log, c.cli.ContentStore(), fetcher),
			), platformMatcher,
		),
	)

	// 3. Dispatch the handler starting from the root descriptor (the Index)
	err = images.Dispatch(ctx, handler, nil, desc)

	img := images.Image{
		Name:   name,
		Target: desc,
		// TODO figure out if we need some additional labels
	}

	is := c.cli.ImageService()
	for {
		if created, err := is.Create(ctx, img); err != nil {
			if !errdefs.IsAlreadyExists(err) {
				return err
			}

			updated, err := is.Update(ctx, img)
			if err != nil {
				// if image was removed, try create again
				if errdefs.IsNotFound(err) {
					continue
				}
				return err
			}
			img = updated
		} else {
			img = created
		}
		break
	}

	mfst, err := images.Manifest(ctx, c.cli.ContentStore(), desc, platformMatcher)
	if err != nil {
		return fmt.Errorf("could not retrieve manifest from store: %w", err)
	}

	diffIDs, err := images.RootFS(ctx, c.cli.ContentStore(), mfst.Config)
	if err != nil {
		return fmt.Errorf("could not retrieve diffIDs from store: %w", err)
	}
	sn := c.cli.SnapshotService(c.driver)

	err = unpackRemoteLayers(ctx, c.log, fetcher, sn, mfst, diffIDs, c.bdb)
	if err != nil {
		return fmt.Errorf("could not unpack layers: %w", err)
	}

	return err
}

func remoteChildren(log logger.Logger, store content.Store, fetcher remotes.Fetcher) images.HandlerFunc {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		switch {
		case images.IsDockerType(desc.MediaType):
			return nil, fmt.Errorf("%v not supported", desc.MediaType)
		case images.IsIndexType(desc.MediaType):
			var index ocispec.Index

			err := fetchAndStoreMetadata(ctx, fetcher, store, desc, &index)
			if err != nil {
				return nil, fmt.Errorf("failed fetching or storing index: %w", err)
			}

			log.Debugf("Stored index manifest with digest: %s", desc.Digest)
			return append([]ocispec.Descriptor{}, index.Manifests...), nil
		case images.IsManifestType(desc.MediaType):
			var manifest ocispec.Manifest

			err := fetchAndStoreMetadata(ctx, fetcher, store, desc, &manifest)
			if err != nil {
				return nil, fmt.Errorf("failed fetching or storing manifest: %w", err)
			}

			log.Debugf("Stored image manifest with digest: %s", desc.Digest)
			return append([]ocispec.Descriptor{manifest.Config}, manifest.Layers...), nil
		case images.IsConfigType(desc.MediaType):
			var config ocispec.Image

			err := fetchAndStoreMetadata(ctx, fetcher, store, desc, &config)
			if err != nil {
				return nil, fmt.Errorf("failed fetching or storing manifest: %w", err)
			}

			log.Debugf("Stored image config with digest: %s", desc.Digest)
			return nil, nil
		case images.IsLayerType(desc.MediaType):
			log.Debugf("encountered a layer type, not fetching it")
		default:
			log.Debugf("encountered unknown type %v; children may not be fetched", desc.MediaType)
		}
		return nil, nil
	}
}

// fetchAndStoreMetadata uses the fetcher to grab a blob and writes it to the content store.
// Metadata contents are deserialized to the given metadata pointer (Manifest or Config).
// This is strictly used for the small non-layer blobs (Manifest and Config).
func fetchAndStoreMetadata(ctx context.Context, fetcher remotes.Fetcher, store content.Store, desc ocispec.Descriptor, metadata any) error {
	// Fetch from the registry
	metadataBytes, err := FetchMetadata(ctx, fetcher, desc)
	if err != nil {
		return nil
	}

	if metadata != nil {
		// Unmarshal config or manifest
		if err := json.Unmarshal(metadataBytes, metadata); err != nil {
			return fmt.Errorf("unmarshalling metadata error: %w", err)
		}
	}

	// Commit it to containerd's content store
	err = content.WriteBlob(ctx, store, desc.Digest.String(), bytes.NewReader(metadataBytes), desc)
	if err != nil {
		return fmt.Errorf("failed to write blob to content store: %w", err)
	}

	return nil
}

// FetchMetadata uses the fetcher to grab a blob and returns blob bytes.
// This is strictly used for the small non-layer blobs (Manifest and Config).
func FetchMetadata(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor) (metadata []byte, err error) {
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

func unpackRemoteLayers(ctx context.Context, log logger.Logger, fetcher remotes.Fetcher, sn snapshots.Snapshotter, manifest ocispec.Manifest, diffIDs []digest.Digest, bdb *bolt.DB) (err error) {
	chainIDs := make([]digest.Digest, len(diffIDs))
	copy(chainIDs, diffIDs)
	chainIDs = identity.ChainIDs(chainIDs)

	var parentChainID, currentChainID string

	for i, layerDesc := range manifest.Layers {
		if i > 0 {
			parentChainID = chainIDs[i-1].String()
		}
		currentChainID = chainIDs[i].String()

		// Check if this layer has already been unpacked in the past
		if _, err := sn.Stat(ctx, currentChainID); err == nil {
			parentChainID = currentChainID
			continue // Skip download, snapshot already exists
		}

		// 5. Prepare a new snapshot directory
		activeKey := fmt.Sprintf("extract-%s", currentChainID)
		mounts, err := sn.Prepare(ctx, activeKey, parentChainID)
		if err != nil {
			return fmt.Errorf("failed to prepare snapshot: %w", err)
		}

		// fetch TOC for zstd:chunked formatted layers
		toc, _, tocOffset, err := fetchZstdTOC(ctx, log, layerDesc, fetcher)
		if err != nil {
			log.Warnf("could not fetch zstd:chunked's TOC, skip TOC fetch: %v", err)
		}

		if toc != nil {
			// 6. Perform and optimized download and extraction based on zstd:chunked
			missing, cached, nodes := processTOC(log, bdb, toc, tocOffset)
			callback := func(root string) error {
				return unpackZstdChunkedLayer(ctx, log, bdb, fetcher, layerDesc, nodes, missing, cached, root)
			}
			err = runAtMountsStack(ctx, mounts, callback)
			if err != nil {
				sn.Remove(ctx, activeKey) // Clean up the active transaction on error
				return fmt.Errorf("unpacking zstd:chunked layers in mounts stack: %w", err)
			}
		} else {
			// 6. Fetch the compressed layer blob directly from the network
			err = fetchAndApplyLayerBlob(ctx, fetcher, layerDesc, mounts)
			if err != nil {
				sn.Remove(ctx, activeKey) // Clean up the active transaction on error
				return fmt.Errorf("failed to apply layer %s: %w", layerDesc.Digest, err)
			}
		}

		// 8. Commit the snapshot to lock it into the immutable state
		// Label added here is just to be consistent with unpacked images, I don't know the motivation of this label
		if err = sn.Commit(ctx, currentChainID, activeKey, snapshots.WithLabels(map[string]string{
			"containerd.io/snapshot.ref": currentChainID,
		})); err != nil {
			if errdefs.IsAlreadyExists(err) {
				return nil
			}
			return err
		}

		// Step forward
		parentChainID = currentChainID
		fmt.Printf("Successfully unpacked layer: %s\n", currentChainID)
	}
	return nil
}

func fetchAndApplyBlobRanges(ctx context.Context, log logger.Logger, fetcher remotes.Fetcher, layerDesc ocispec.Descriptor, root string, ranges []*byteRangeGroup) error {
	var currentStreamPos int64
	for _, blobRange := range ranges {
		// fetch the range as a new compressed stream, the new compressed stream starts reading from position 0
		rc, err := fetchRange(ctx, fetcher, layerDesc, blobRange.StartOffset, blobRange.EndOffset-blobRange.StartOffset+1)
		if err != nil {
			return fmt.Errorf("fetching layer chunk for %d files: %w", len(blobRange.Files), err)
		}

		currentStreamPos = blobRange.StartOffset
		for _, zstdFile := range blobRange.Files {
			path := filepath.Join(root, zstdFile.Name)
			// discard gaps between files
			if currentStreamPos < zstdFile.Range.Offset {
				gap := zstdFile.Range.Offset - currentStreamPos
				_, err := io.CopyN(io.Discard, rc, gap)
				if err != nil {
					return fmt.Errorf("discarting gaps between ranges: %w", err)
				}
				currentStreamPos += gap
			}

			log.Debugf("extracting file %s. Offset %d, endoffset %d, size %d", path, currentStreamPos, blobRange.EndOffset, zstdFile.Range.Size)

			// remove target file if already exists and recreate it as an empty file
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				rc.Close()
				return err
			}
			outFile, err := os.Create(path)
			if err != nil {
				rc.Close()
				return err
			}

			// ensure reader does not go beyond the actual file
			rangeReader := io.LimitReader(rc, zstdFile.Range.Size)
			decompressedStream, err := zstd.NewReader(rangeReader)
			if err != nil {
				rc.Close()
				outFile.Close()
				return fmt.Errorf("uncompressing stream for file %s", zstdFile.Name)
			}

			// write the file with the decompressed data
			_, err = io.Copy(outFile, decompressedStream)
			decompressedStream.Close()
			// Swallow unexpected EOF error if we are reading the last file chunk, not sure why this error is raised
			// neither if this is a relevant problem. TODO verify the decompressed size matches the expected one
			if errors.Is(err, io.ErrUnexpectedEOF) && currentStreamPos+zstdFile.Range.Size-1 == blobRange.EndOffset {
				err = nil
			}
			if err != nil {
				rc.Close()
				outFile.Close()
				return fmt.Errorf("writing %s: %w", path, err)
			}
			err = outFile.Close()
			if err != nil {
				rc.Close()
				return fmt.Errorf("closing uncompressed file %s: %w", path, err)
			}

			// update stream position, this is needed to jump gaps
			currentStreamPos += zstdFile.Range.Size
		}
	}
	return nil
}

func applyCachedFiles(ctx context.Context, log logger.Logger, cached []*tocFile, root string) error {
	return nil
}

func updateZstdCacheDB(ctx context.Context, log logger.Logger, bdb *bolt.DB, missing []*byteRangeGroup, cached []*tocFile) error {
	return nil
}

func createStructuralNodes(ctx context.Context, log logger.Logger, nodes []*estargz.TOCEntry, root string) error {
	var err error
	var path string

	// sort paths to ensure we are starting from parent directories
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })

	for _, e := range nodes {
		path = filepath.Join(root, e.Name)
		switch e.Type {
		case "reg":
			if e.Size != 0 || e.Digest != "" {
				log.Warn("non zero 'reg' entry type found (%s), ignoring it", e.Name)
			}
		case "dir":
			_, err = os.Stat(path)
			if err == nil {
				err = os.Chmod(path, e.Stat().Mode())
			}
			if errors.Is(err, fs.ErrNotExist) {
				err = os.MkdirAll(path, e.Stat().Mode())
			}
			if err != nil {
				return fmt.Errorf("creating directory %s: %w", path, err)
			}
		case "symlink":
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return err
			}

			err = os.Symlink(e.LinkName, path)
			if err != nil {
				return fmt.Errorf("creating symlink %s -> %s: %w", path, e.LinkName, err)
			}
		case "hardlink":
			log.Warn("'hardlink' entry type found (%s). Hardlinks not supported yet, not creating it", e.Name)
		case "char", "block":
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			dev := unix.Mkdev(uint32(e.DevMajor), uint32(e.DevMinor))
			err := unix.Mknod(path, uint32(e.Mode), int(dev))
			if err != nil {
				return fmt.Errorf("creating char device %s: %w", path, err)
			}
		case "fifo":
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			err := unix.Mkfifo(path, uint32(e.Mode))
			if err != nil {
				return fmt.Errorf("creating the fifo file %s: %w", path, err)
			}
		case "chunk":
			log.Warn("'chunk' entry type found in structural nodes list, ignoring it")
		}
	}
	return nil
}

func unpackZstdChunkedLayer(
	ctx context.Context, log logger.Logger, bdb *bolt.DB, fetcher remotes.Fetcher, desc ocispec.Descriptor,
	nodes []*estargz.TOCEntry, missing []*byteRangeGroup, cached []*tocFile, root string,
) error {
	// 6.2 Create all special nodes
	err := createStructuralNodes(ctx, log, nodes, root)
	if err != nil {
		return err
	}

	// 6.3 fetch and extract missing files
	err = fetchAndApplyBlobRanges(ctx, log, fetcher, desc, root, missing)
	if err != nil {
		return err
	}

	// 6.4 appplied cached files
	err = applyCachedFiles(ctx, log, cached, root)
	if err != nil {
		return err
	}

	// 6.5 Update cache DB
	err = updateZstdCacheDB(ctx, log, bdb, missing, cached)
	if err != nil {
		return err
	}
	return nil
}

// fetchAndApplyLayerBlob runs a common and generic layer blob download and unpack to the given mounts stack
func fetchAndApplyLayerBlob(ctx context.Context, fetcher remotes.Fetcher, layerDesc ocispec.Descriptor, mounts []mount.Mount) error {
	rc, err := fetcher.Fetch(ctx, layerDesc)
	if err != nil {
		return fmt.Errorf("failed to fetch layer %s: %w", layerDesc.Digest, err)
	}

	uncompressedStream, err := compression.DecompressStream(rc)
	if err != nil {
		return fmt.Errorf("setting the uncompressed stream reader: %w", err)
	}

	// 7. Apply the tar stream directly to the snapshotter's mounts
	err = applyUnix(ctx, mounts, uncompressedStream, true)
	uErr := uncompressedStream.Close()
	if err == nil && uErr != nil {
		err = uErr
	}
	cErr := rc.Close()
	if err == nil && cErr != nil {
		err = cErr
	}
	return err
}

type readCloser struct {
	io.Reader
	close func()
}

func (r readCloser) Close() error {
	r.close()
	return nil
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

// setupResolver creates a new resolver with a custom http client with the http.RoundTripper
// to support ranged http requests.
// TODO: expose resolver configuration options as optional parametres
func setupResolver() remotes.Resolver {
	customClient := &http.Client{
		Transport: &rangeRoundTripper{
			Base: http.DefaultTransport,
		},
	}

	// Initialize the resolver with our customized client
	opts := docker.ResolverOptions{
		Client: customClient,
		// You can also add your registry hosts / auth configurations here
		// TODO: I don't know why adding this causes to ignore the custom client
		//Hosts: docker.ConfigureDefaultRegistries(),
	}

	return docker.NewResolver(opts)
}

func fetchRange(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor, offset int64, size int64) (io.ReadCloser, error) {
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

// TODO ensure the fetcher includes our custom RoundTripper, probably define our own type alias for the fetcher or pass our custom resolver type
func fetchZstdTOC(ctx context.Context, log logger.Logger, layerDesc ocispec.Descriptor, fetcher remotes.Fetcher) (*estargz.JTOC, digest.Digest, int64, error) {
	var tocDgst digest.Digest

	if layerDesc.MediaType != ocispec.MediaTypeImageLayerZstd {
		// We do nothing if the layer is not of zstd type
		log.Debugf("%s is not a zstd layer, no TOC to fecth", layerDesc.Digest.String())
		return nil, tocDgst, 0, nil
	}

	if val, ok := layerDesc.Annotations[zstdchunked.ManifestChecksumAnnotation]; ok {
		log.Debugf("annotation points to zstd:chunked format. Checksum: %s", val)
	}

	decompressor := new(zstdchunked.Decompressor)
	footerSize := decompressor.FooterSize()

	rc, err := fetchRange(ctx, fetcher, layerDesc, layerDesc.Size-footerSize, footerSize)
	if err != nil {
		return nil, tocDgst, 0, fmt.Errorf("fetching blob footer: %w", err)
	}
	footerBytes, err := io.ReadAll(rc)
	cErr := rc.Close()
	if err != nil {
		return nil, tocDgst, 0, fmt.Errorf("reading zstd footer bytes: %w", err)
	}
	if cErr != nil {
		return nil, tocDgst, 0, fmt.Errorf("closing footer reader: %w", err)
	}

	_, tocOff, tocSize, err := decompressor.ParseFooter(footerBytes)
	if err != nil {
		// We assume this is not of zstd:chunked type and process normally
		log.Debugf("could not parse zstd TOC from footer: %w", err)
		return nil, tocDgst, 0, nil
	}

	if tocSize <= 0 {
		log.Warnf("inconsistent TOC size (%d) detected, ignoring TOC", tocSize)
		return nil, tocDgst, 0, nil
	}

	rc, err = fetchRange(ctx, fetcher, layerDesc, tocOff, tocSize)
	if err != nil {
		return nil, tocDgst, 0, fmt.Errorf("fetching TOC: %w", err)
	}

	toc, tocDgst, err := decompressor.ParseTOC(rc)
	cErr = rc.Close()
	if err != nil {
		return nil, tocDgst, 0, fmt.Errorf("decompressing TOC: %w", err)
	}
	if cErr != nil {
		return nil, tocDgst, 0, fmt.Errorf("closing TOC reader: %w", err)
	}
	log.Debugf("uncompressed TOC with %d entries and digest %s", len(toc.Entries), tocDgst.String())

	return toc, tocDgst, tocOff, nil
}

// tocFile represents an entire file, aggregating the bytes range of the initial
// reg entry and any subsequent chunk entries
type tocFile struct {
	Name        string
	Digest      string
	IsCacheHit  bool
	CachedPaths []string
	Range       *byteRange
}

type byteRange struct {
	Offset int64
	Size   int64
}

// byteRangeGroup represents a coalesced HTTP Range request for one or more files
type byteRangeGroup struct {
	StartOffset int64
	EndOffset   int64
	Files       []*tocFile
}

func processTOC(log logger.Logger, bdb *bolt.DB, toc *estargz.JTOC, tocOffset int64) (ranges []*byteRangeGroup, cached []*tocFile, specialNodes []*estargz.TOCEntry) {
	var active *tocFile
	var missing []*tocFile

	// Helper function to evaluate the fully grouped file
	queueActiveFile := func(file *tocFile) {
		if file.IsCacheHit {
			// Cache Hit: The whole file is cached. Ignore the chunks and queue the reflink.
			cached = append(cached, file)
		} else {
			// Cache Miss: Queue the range chunk for download.
			missing = append(missing, file)
		}
	}

	sort.Slice(toc.Entries, func(i, j int) bool {
		return toc.Entries[i].Offset < toc.Entries[j].Offset
	})

	var nextOffset int64
	for i, entry := range toc.Entries {
		if i+1 == len(toc.Entries) {
			nextOffset = tocOffset - 1
		} else {
			nextOffset = toc.Entries[i+1].Offset
		}

		// 1. If it's a chunk, append it to the currently active file
		if entry.Type == "chunk" {
			if active != nil && active.Name == entry.Name {
				active.Range.Size = nextOffset - active.Range.Offset
			}
			continue
		}

		// 2. If we reach a new file/node, the previous activeFile is fully grouped
		if active != nil {
			queueActiveFile(active)
			active = nil // Reset
		}

		// 3. Handle the new entry based on its type
		switch entry.Type {
		case "reg":
			if entry.Size == 0 || entry.Digest == "" {
				specialNodes = append(specialNodes, entry)
				continue
			}
			// Query bbolt using the WHOLE file digest
			paths, err := getCachedPaths(bdb, entry.Digest)
			if err != nil {
				log.Warnf("error getting cached paths for digest %s, considering it a cache miss. err: %s", entry.Digest, err.Error())
			}

			active = &tocFile{
				Name:        entry.Name,
				Digest:      entry.Digest,
				IsCacheHit:  len(paths) > 0,
				CachedPaths: paths,
				Range: &byteRange{
					Offset: entry.Offset,
					Size:   nextOffset - entry.Offset,
				}, // The 'reg' entry contains the first chunk's payload coordinates
			}

		case "dir", "symlink", "hardlink", "char", "block", "fifo":
			specialNodes = append(specialNodes, entry)
		}
	}

	// Don't forget to queue the very last file in the TOC
	if active != nil {
		queueActiveFile(active)
	}
	ranges = groupMissingFiles(missing)

	log.Debugf("collected %d individual missing ranges, but coalesced them to %d missing ranges", len(missing), len(ranges))
	log.Debugf("collected %d reflink tasks", len(cached))

	return ranges, cached, specialNodes
}

func groupMissingFiles(misses []*tocFile) []*byteRangeGroup {
	if len(misses) == 0 {
		return nil
	}

	sort.Slice(misses, func(i, j int) bool {
		return misses[i].Range.Offset < misses[j].Range.Offset
	})

	var groups []*byteRangeGroup
	var current *byteRangeGroup

	// Define a threshold (e.g., 128KB) where it is cheaper to download
	// the gap than to initiate a new HTTP request. He want to optimize
	// downloads rather than the decoding process of the compressed stream.
	const gapThreshold int64 = 128 * 1024

	for _, miss := range misses {
		if current == nil {
			current = &byteRangeGroup{
				StartOffset: miss.Range.Offset,
				EndOffset:   miss.Range.Offset + miss.Range.Size - 1,
				Files:       []*tocFile{miss},
			}
			continue
		}

		// Calculate the physical byte gap between the current group and the next chunk
		gap := miss.Range.Offset - (current.EndOffset + 1)

		if gap >= 0 && gap <= gapThreshold {
			// The gap is small enough. Merge this chunk into the current HTTP request.
			current.EndOffset = miss.Range.Offset + miss.Range.Size - 1
			current.Files = append(current.Files, miss)
			continue
		}
		// The gap is too large. Save the current group and start a new one.
		groups = append(groups, current)
		current = &byteRangeGroup{
			StartOffset: miss.Range.Offset,
			EndOffset:   miss.Range.Offset + miss.Range.Size - 1,
			Files:       []*tocFile{miss},
		}
	}

	if current != nil {
		groups = append(groups, current)
	}

	return groups
}

// getCachedPaths returns a list of local paths where the uncompressed chunk resides
func getCachedPaths(bdb *bolt.DB, chunkDigest string) ([]string, error) {
	var paths []string

	err := bdb.View(func(tx *bolt.Tx) error {
		// Traverse the bucket hierarchy safely
		root := tx.Bucket([]byte(TopLevelBucket))
		if root == nil {
			return nil // Cache doesn't exist yet
		}

		locBucket := root.Bucket([]byte(ChunkLocBucket))
		if locBucket == nil {
			return nil
		}

		// Fetch the JSON array
		data := locBucket.Get([]byte(chunkDigest))
		if data != nil {
			if err := json.Unmarshal(data, &paths); err != nil {
				return err
			}
		}
		return nil
	})

	return paths, err
}

// recordChunk updates the cache to link a chunk digest to its new physical path
func recordChunk(db *bolt.DB, snapshotKey string, chunkDigest string, newPath string) error {
	return db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(TopLevelBucket))
		locBucket := root.Bucket([]byte(ChunkLocBucket))
		snapBucket := root.Bucket([]byte(SnapshotChunkBucket))

		// --- 1. Update Forward Index ---
		var paths []string
		if data := locBucket.Get([]byte(chunkDigest)); data != nil {
			json.Unmarshal(data, &paths)
		}

		// Deduplicate: Ensure we don't add the same path twice
		pathExists := slices.Contains(paths, newPath)
		if !pathExists {
			paths = append(paths, newPath)
			encodedPaths, _ := json.Marshal(paths)
			locBucket.Put([]byte(chunkDigest), encodedPaths)
		}

		// --- 2. Update Reverse Index ---
		var digests []string
		if data := snapBucket.Get([]byte(snapshotKey)); data != nil {
			json.Unmarshal(data, &digests)
		}

		digestExists := slices.Contains(digests, chunkDigest)
		if !digestExists {
			digests = append(digests, chunkDigest)
			encodedDigests, _ := json.Marshal(digests)
			snapBucket.Put([]byte(snapshotKey), encodedDigests)
		}

		return nil
	})
}

func runAtMountsStack(ctx context.Context, mounts []mount.Mount, callback func(root string) error) (err error) {
	switch {
	case len(mounts) == 1 && mounts[0].Type == "overlay":
		// OverlayConvertWhiteout (mknod c 0 0) doesn't work in userns.
		// https://github.com/containerd/containerd/issues/3762
		if userns.RunningInUserNS() {
			break
		}
		path, _, err := getOverlayPath(mounts[0].Options)
		if err != nil {
			if errdefs.IsInvalidArgument(err) {
				break
			}
			return err
		}
		// TODO consider the need of computing the equivalent of
		// archive.WithConvertWhiteout and archive.WithParents
		err = callback(path)
		if err == nil {
			err = doSyncFs(path)
		}
		return err
	case len(mounts) == 1 && mounts[0].Type == "bind":
		defer func() {
			if err != nil {
				return
			}
			err = doSyncFs(mounts[0].Source)
		}()
	}
	return mount.WithTempMount(ctx, mounts, func(root string) error {
		return callback(root)
	})
}

// From here up to the and of the file the code is copied form containerd
// https://github.com/containerd/containerd/blob/main/core/diff/apply/apply_linux.go
// There is no public differ API to apply changes from a Reader. In fact this is just
// a small wrapper around archive.Apply which is public, this handles some specific corner
// cases which are related to the underlaying differ and snapshotter.

func applyUnix(ctx context.Context, mounts []mount.Mount, r io.Reader, sync bool) (retErr error) {
	switch {
	case len(mounts) == 1 && mounts[0].Type == "overlay":
		// OverlayConvertWhiteout (mknod c 0 0) doesn't work in userns.
		// https://github.com/containerd/containerd/issues/3762
		if userns.RunningInUserNS() {
			break
		}
		path, parents, err := getOverlayPath(mounts[0].Options)
		if err != nil {
			if errdefs.IsInvalidArgument(err) {
				break
			}
			return err
		}
		opts := []archive.ApplyOpt{
			archive.WithConvertWhiteout(archive.OverlayConvertWhiteout),
		}
		if len(parents) > 0 {
			opts = append(opts, archive.WithParents(parents))
		}
		_, err = archive.Apply(ctx, path, r, opts...)
		if err == nil && sync {
			err = doSyncFs(path)
		}
		return err
	case sync && len(mounts) == 1 && mounts[0].Type == "bind":
		defer func() {
			if retErr != nil {
				return
			}

			retErr = doSyncFs(mounts[0].Source)
		}()
	}
	return mount.WithTempMount(ctx, mounts, func(root string) error {
		_, err := archive.Apply(ctx, root, r)
		return err
	})
}

func getOverlayPath(options []string) (upper string, lower []string, err error) {
	const upperdirPrefix = "upperdir="
	const lowerdirPrefix = "lowerdir="

	for _, o := range options {
		if strings.HasPrefix(o, upperdirPrefix) {
			upper = strings.TrimPrefix(o, upperdirPrefix)
		} else if strings.HasPrefix(o, lowerdirPrefix) {
			lower = strings.Split(strings.TrimPrefix(o, lowerdirPrefix), ":")
		}
	}
	if upper == "" {
		return "", nil, fmt.Errorf("upperdir not found: %w", errdefs.ErrInvalidArgument)
	}

	return
}

func doSyncFs(file string) error {
	fd, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", file, err)
	}
	defer fd.Close()

	err = unix.Syncfs(int(fd.Fd()))
	if err != nil {
		return fmt.Errorf("failed to syncfs for %s: %w", file, err)
	}
	return nil
}
