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
	"maps"
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

const ActiveSnap = "activeSnap"

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
			pTOC := processTOC(log, bdb, toc, tocOffset)
			callback := func(root string) error {
				return unpackZstdChunkedLayer(ctx, log, bdb, fetcher, layerDesc, pTOC, root, currentChainID, sn)
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

func fetchAndApplyBlobRanges(ctx context.Context, log logger.Logger, fetcher remotes.Fetcher, layerDesc ocispec.Descriptor, root string, pTOC *processedTOC) (err error) {
	var currentStreamPos int64
	var ranges []*byteRangeGroup

	// TODO we could also group missing files based on range size to parallelize the download and extraction of big layers
	ranges = groupMissingFiles(pTOC.missingFiles)

	log.Debugf("coalesced the range of %d files into %d multifile ranges", len(pTOC.missingFiles), len(ranges))

	for _, blobRange := range ranges {
		// fetch the range as a new compressed stream, the new compressed stream starts reading from position 0
		rc, err := fetchRange(ctx, fetcher, layerDesc, blobRange.StartOffset, blobRange.EndOffset-blobRange.StartOffset+1)
		if err != nil {
			return fmt.Errorf("fetching layer chunk for %d files: %w", len(blobRange.Files), err)
		}
		defer func() {
			cErr := rc.Close()
			if err == nil && cErr != nil {
				err = fmt.Errorf("closing stream from range fetcher: %w", cErr)
			}
		}()

		currentStreamPos = blobRange.StartOffset
		for _, zstdFile := range blobRange.Files {

			// discard gaps between files
			if currentStreamPos < zstdFile.Range.Offset {
				gap := zstdFile.Range.Offset - currentStreamPos
				_, err := io.CopyN(io.Discard, rc, gap)
				if err != nil {
					return fmt.Errorf("discarting gaps between ranges: %w", err)
				}
				currentStreamPos += gap
			}

			err = decompressFile(log, rc, zstdFile, root)
			if err != nil {
				return fmt.Errorf("decompressing file (%s) from zstd:chunked file range: %w", zstdFile.Entry.Name, err)
			}

			// update stream position, this is needed to jump gaps
			currentStreamPos += zstdFile.Range.Size
		}
	}
	return nil
}

// TODO limit rc to read only (no close) and limit outFile to io.Writer
func decompressFile(log logger.Logger, rc io.ReadCloser, zstdFile *tocFile, root string) (err error) {
	// remove target file if already exists and recreate it as an empty file
	path := filepath.Join(root, zstdFile.Entry.Name)
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	outFile, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(zstdFile.Entry.Mode))
	if err != nil {
		return err
	}
	defer func() {
		cErr := outFile.Close()
		if err == nil && cErr != nil {
			err = fmt.Errorf("closing output file %s: %w", path, cErr)
		}
		if err == nil {
			err = applyMetadata(path, zstdFile.Entry)
			if err != nil {
				err = fmt.Errorf("applying metadata to file %s: %w", path, err)
			}
		}
	}()

	// limit the range to avoid reading next file
	rangeReader := io.LimitReader(rc, zstdFile.Range.Size)
	decompressedStream, err := zstd.NewReader(rangeReader)
	if err != nil {
		return fmt.Errorf("uncompressing stream for file %s", zstdFile.Entry.Name)
	}
	defer decompressedStream.Close()

	// limit the copy to skip tar headers
	written, err := io.CopyN(outFile, decompressedStream, zstdFile.Entry.Size)
	if written != zstdFile.Entry.Size {
		log.Warnf("written bytes (%d) not matching expected size (%d)", written, zstdFile.Entry.Size)
	}
	if err != nil {
		return fmt.Errorf("writing bytes for file %s: %w", zstdFile.Entry.Name, err)
	}
	// discard tar headers
	_, err = io.Copy(io.Discard, decompressedStream)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// TODO: I don't know why I always get a io.ErrUnexpectedEOF for the last file
		log.Debugf("Unexpected EOF when discarting bytes from uncompressed stream: %s", err.Error())
		return nil
	}
	if err != nil {
		return fmt.Errorf("discarting bytes from uncompressed stream: %w", err)
	}
	return nil
}

func applyCachedFiles(ctx context.Context, log logger.Logger, sn snapshots.Snapshotter, pTOC *processedTOC, root string) error {
	var appliedIdx int
	applied := make([]int, len(pTOC.cachedFiles))

	onSnapshotCallback := func(snapshotKey string) func(snapRoot string) error {
		return func(snapRoot string) error {
			var mErr error
			for _, idx := range pTOC.reverseCacheIdx[snapshotKey] {
				if idx >= len(pTOC.cachedFiles) {
					log.Warnf("inconsistend index found in reverse cache index: %d", idx)
					continue
				}
				if slices.Contains(applied, idx) {
					continue
				}

				var src, tgt string
				tgt = filepath.Join(root, pTOC.cachedFiles[idx].Entry.Name)
				srcPaths := pTOC.cachedFiles[idx].CachedPaths.GetPathsBySnapshot(snapshotKey)
				for _, srcPath := range srcPaths {
					src = filepath.Join(snapRoot, srcPath)
					if err := reflinkOrCopy(tgt, src, pTOC.cachedFiles[idx].Entry); err == nil {
						applied[appliedIdx] = idx
						appliedIdx++
						break
					} else {
						mErr = errors.Join(mErr, err)
					}
				}
			}
			return mErr
		}
	}

	var errs error
	for snapshotKey := range maps.Keys(pTOC.reverseCacheIdx) {
		callback := onSnapshotCallback(snapshotKey)
		if snapshotKey == ActiveSnap {
			// these are a duplicted files within the same remote layer, just downloaded one
			// other are applied from the already extrated remote files
			errs = errors.Join(errs, callback(root))
			continue
		}
		mnts, err := sn.View(ctx, snapshotKey, "")
		if err != nil {
			errs = errors.Join(errs, err)
			log.Warnf("something went wrong preparing snapshot %s: %s", snapshotKey, err.Error())
			continue
		}
		errs = errors.Join(errs, runAtMountsStack(ctx, mnts, callback))
	}

	if errs != nil {
		return fmt.Errorf("one or more erros occurred applying cached files: %w", errs)
	}

	log.Debugf("applied %d files from cache", len(applied))
	if appliedIdx != len(pTOC.cachedFiles)-1 {
		return fmt.Errorf("applied %d files, but we were expecting to apply %d", appliedIdx+1, len(pTOC.cachedFiles))
	}
	return nil
}

func reflinkOrCopy(target, source string, entry *estargz.TOCEntry) (err error) {
	src, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("opening file %s: %w", source, err)
	}
	defer func() {
		cErr := src.Close()
		if err == nil && cErr != nil {
			err = cErr
		}
	}()

	srcInfo, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat file %s: %w", source, err)
	}

	if !srcInfo.Mode().IsRegular() {
		return fmt.Errorf("non-regular source file: %s", source)
	}

	// Create destination with same permissions initially
	dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(0700))
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			dst.Close()
			os.Remove(target)
		}
	}()

	// Attempt reflink clone
	err = unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
	if err != nil {
		// If reflink unsupported or cross-device, fallback
		if errors.Is(err, unix.EOPNOTSUPP) ||
			errors.Is(err, unix.EXDEV) ||
			errors.Is(err, unix.EINVAL) {

			// Reset file offset before copy
			if _, seekErr := src.Seek(0, 0); seekErr != nil {
				return fmt.Errorf("seeking file %s before copying: %w", source, err)
			}

			if _, copyErr := io.Copy(dst, src); copyErr != nil {
				return fmt.Errorf("copying %s to %s: %w", source, target, err)
			}
		} else {
			return fmt.Errorf("reflinking from %s to %s: %w", source, target, err)
		}
	}

	// Sync to ensure durability
	err = dst.Sync()
	if err != nil {
		return fmt.Errorf("synching target file %s: %w", target, err)
	}

	err = dst.Close()
	if err != nil {
		return fmt.Errorf("closing file %s: %w", target, err)
	}

	err = applyMetadata(target, entry)
	if err != nil {
		return fmt.Errorf("applying metadata to target file %s: %w", target, err)
	}

	return nil
}

func createStructuralNodes(log logger.Logger, pTOC *processedTOC, root string) (pending []*estargz.TOCEntry, err error) {
	var path string

	// sort paths to ensure we are starting from parent directories
	nodes := pTOC.structure
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })

	for _, e := range nodes {
		path = filepath.Join(root, e.Name)
		goMode := os.FileMode(e.Mode)
		permBits := uint32(goMode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
		switch e.Type {
		case "reg":
			if e.Size != 0 || e.Digest != "" {
				log.Warn("non zero 'reg' entry type found (%s), ignoring it", e.Name)
				continue
			}
			flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
			file, err := os.OpenFile(path, flags, goMode.Perm())
			if err != nil {
				return nil, fmt.Errorf("creating file %s: %w", path, err)
			}
			err = file.Close()
			if err != nil {
				return nil, fmt.Errorf("closing file %s: %w", path, err)
			}
		case "dir":
			_, err = os.Stat(path)
			if err == nil {
				err = os.Chmod(path, os.FileMode(0700))
			}
			if errors.Is(err, fs.ErrNotExist) {
				err = os.MkdirAll(path, os.FileMode(0700))
			}
			if err != nil {
				return nil, fmt.Errorf("creating directory %s: %w", path, err)
			}
			// apply metadata and permissions to directories as the last step
			pending = append(pending, e)
			continue
		case "symlink":
			//TODO sanitize links, links going out of the tree shouldn't be allowed!
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}

			err = os.Symlink(e.LinkName, path)
			if err != nil {
				return nil, fmt.Errorf("creating symlink %s -> %s: %w", path, e.LinkName, err)
			}
		case "hardlink":
			// apply hardlinks after applying cached and fetched files
			pending = append(pending, e)
			continue
		case "char", "block":
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			mode := permBits | unix.S_IFCHR
			if e.Type == "block" {
				mode = permBits | unix.S_IFBLK
			}
			dev := unix.Mkdev(uint32(e.DevMajor), uint32(e.DevMinor))
			err := unix.Mknod(path, mode, int(dev))
			if err != nil {
				return nil, fmt.Errorf("creating char device %s: %w", path, err)
			}
		case "fifo":
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			err := unix.Mkfifo(path, permBits|unix.S_IFIFO)
			if err != nil {
				return nil, fmt.Errorf("creating the fifo file %s: %w", path, err)
			}
		case "chunk":
			log.Warn("'chunk' entry type found in structural nodes list, ignoring it")
			continue
		}
		err = applyMetadata(path, e)
		if err != nil {
			return nil, fmt.Errorf("failed applying GID, UID or Xattrs to %s: %w", path, err)
		}
	}
	return pending, nil
}

// applyMetadata sets the UID, GID, MTime and Extended Attributes on a created node
func applyMetadata(targetPath string, entry *estargz.TOCEntry) error {
	// If targetPath is a symlink, Lchown changes the symlink itself.
	if err := os.Lchown(targetPath, entry.UID, entry.GID); err != nil {
		return fmt.Errorf("failed to apply Lchown to %s: %w", targetPath, err)
	}

	if entry.ModTime3339 != "" {
		modTime, err := time.Parse(time.RFC3339, entry.ModTime3339)
		if err != nil {
			return fmt.Errorf("parsing timestamp %s of file %s: %w", entry.ModTime3339, targetPath, err)
		}

		var ts [2]unix.Timespec
		// ATime fallback to MTime
		ts[0] = unix.NsecToTimespec(modTime.UnixNano())
		// MTime
		ts[1] = unix.NsecToTimespec(modTime.UnixNano())

		// Do not follow symlinks
		err = unix.UtimesNanoAt(unix.AT_FDCWD, targetPath, ts[:], unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return fmt.Errorf("failed to apply timestamps to %s: %w", targetPath, err)
		}
	}

	for name, value := range entry.Xattrs {
		// The '0' flag means "create or replace".
		err := unix.Lsetxattr(targetPath, name, value, 0)
		if err != nil {
			// Note: Some xattrs requires privileges (e.g. CAP_SYS_ADMIN)
			return fmt.Errorf("failed to set xattr %s on %s: %w", name, targetPath, err)
		}
	}
	return nil
}

func applyPendingNodes(log logger.Logger, pending []*estargz.TOCEntry, root string) error {
	var path string
	var err error

	// in reverse order to ensure we do not fall in the readonly trap
	slices.Reverse(pending)

	for _, e := range pending {
		path = filepath.Join(root, e.Name)
		goMode := os.FileMode(e.Mode)
		switch e.Type {
		case "dir":
			err = os.Chmod(path, goMode.Perm())
			if err != nil {
				return fmt.Errorf("setting permissions for directory %s: %w", path, err)
			}
		case "hardlink":
			linkTarget := filepath.Join(root, e.LinkName)
			err = os.Link(linkTarget, path)
			if err != nil {
				return fmt.Errorf("creating hardlink %s -> %s: %w", path, linkTarget, err)
			}
		default:
			log.Warnf("found file of type %s (%s) in pending list, ignoring it", e.Type, path)
			continue
		}
		err = applyMetadata(path, e)
		if err != nil {
			return fmt.Errorf("setting metadata for %s: %w", path, err)
		}
	}
	return nil
}

func unpackZstdChunkedLayer(
	ctx context.Context, log logger.Logger, bdb *bolt.DB, fetcher remotes.Fetcher,
	desc ocispec.Descriptor, pTOC *processedTOC, root, snapshotKey string, sn snapshots.Snapshotter,
) error {
	// 6.2 Create all special nodes
	pending, err := createStructuralNodes(log, pTOC, root)
	if err != nil {
		return err
	}

	// TODO fetches could be parallelized for simultaneous downloads and extractions
	// 6.3 fetch and extract missing files
	err = fetchAndApplyBlobRanges(ctx, log, fetcher, desc, root, pTOC)
	if err != nil {
		return err
	}

	// TODO reflinking cached files could be parallelized too, checking out if it is worth or not would be interesting
	// 6.4 appplied cached files
	err = applyCachedFiles(ctx, log, sn, pTOC, root)
	if err != nil {
		return err
	}

	// 6.5 handle hardlinks and directories metadata in reverse order
	err = applyPendingNodes(log, pending, root)
	if err != nil {
		return err
	}

	// 6.6 Update cache DB
	err = updateZstdCacheDB(log, bdb, pTOC, snapshotKey)
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
	Entry       *estargz.TOCEntry
	CachedPaths cachedPaths
	Range       *byteRange
}

type cachedPath struct {
	SnapshotKey string
	Paths       []string
}

type cachedPaths []*cachedPath

type byteRange struct {
	Offset int64
	Size   int64
}

type processedTOC struct {
	// missing files listed by ascending byte range, these are meant to be fetched from the remote layer
	missingFiles []*tocFile

	// already cached files listed by ascending byte range, these are meant to be found in the system already
	cachedFiles []*tocFile

	// keys are snapshotKeys and the value is a list of indexes in cachedFiles
	reverseCacheIdx map[string][]int

	// index of TOC files ascessible by digest (only missing or cached TOC files)
	digestsIdx map[string][]*tocFile

	// these are structural nodes manually created (dirs, symlinks, hardlinks, devices, etc.)
	structure []*estargz.TOCEntry
}

// byteRangeGroup represents a coalesced HTTP Range request for one or more files
type byteRangeGroup struct {
	StartOffset int64
	EndOffset   int64
	Files       []*tocFile
}

func (cps cachedPaths) GetPathsBySnapshot(snapshotKey string) []string {
	for _, cp := range cps {
		if cp.SnapshotKey == snapshotKey {
			return cp.Paths
		}
	}
	return []string{}
}

func (cps cachedPaths) AddCachedPaths(snapshotKey string, paths ...string) (cachedPaths, bool) {
	var updated bool
	for _, cp := range cps {
		if cp.SnapshotKey == snapshotKey {
			for _, path := range paths {
				if !slices.Contains(cp.Paths, path) {
					cp.Paths = append(cp.Paths, path)
					updated = true
				}
			}
			return cps, updated
		}
	}
	return append(cps, &cachedPath{SnapshotKey: snapshotKey, Paths: paths}), true
}

// TODO we are not optimizing any duplicate files that could be in the same layer, we are not detecting those
// probably we could pre-cache before fetching
func processTOC(log logger.Logger, bdb *bolt.DB, toc *estargz.JTOC, tocOffset int64) *processedTOC {
	var active *tocFile
	var missing, cached []*tocFile
	var structure []*estargz.TOCEntry
	digests := map[string][]*tocFile{}
	reverseIdx := map[string][]int{}

	// Helper function to evaluate the fully grouped file
	queueActiveFile := func(file *tocFile) {
		if len(file.CachedPaths) > 0 {
			// Cache Hit: The whole file is cached. Ignore the chunks and queue the reflink.
			cached = append(cached, file)
			for _, cp := range file.CachedPaths {
				idxs := reverseIdx[cp.SnapshotKey]
				if len(idxs) == 0 {
					reverseIdx[cp.SnapshotKey] = []int{len(cached) - 1}
				} else {
					reverseIdx[cp.SnapshotKey] = append(idxs, len(cached)-1)
				}
			}
		} else {
			// Cache Miss: Queue the range chunk for download.
			missing = append(missing, file)
		}
	}

	// TODO probably it can be assumed this is already the case, it doesn't make
	// sense the entry list if they are not sorted by range
	sort.Slice(toc.Entries, func(i, j int) bool {
		return toc.Entries[i].Offset < toc.Entries[j].Offset
	})

	var nextOffset int64
	for i, entry := range toc.Entries {
		if i+1 == len(toc.Entries) {
			nextOffset = tocOffset
		} else {
			nextOffset = toc.Entries[i+1].Offset
		}

		// if it's a chunk, append it to the currently active file
		if entry.Type == "chunk" {
			if active != nil && active.Entry.Name == entry.Name {
				active.Range.Size = nextOffset - active.Range.Offset
			}
			continue
		}

		// if we reach a new file/node, the previous activeFile is fully grouped
		if active != nil {
			queueActiveFile(active)
			active = nil // Reset
		}

		// handle the new entry based on its type
		switch entry.Type {
		case "reg":
			if entry.Size == 0 || entry.Digest == "" {
				structure = append(structure, entry)
				continue
			}
			// query bbolt using the whole file digest
			paths, err := getDigest(bdb, entry.Digest)
			if err != nil {
				log.Warnf("error getting cached paths for digest %s, considering it a cache miss. err: %s", entry.Digest, err.Error())
			}

			// The 'reg' entry contains the first chunk's payload coordinates
			active = &tocFile{
				Entry:       entry,
				CachedPaths: paths,
				Range: &byteRange{
					Offset: entry.Offset,
					Size:   nextOffset - entry.Offset,
				},
			}

			// consider duplicated missing digests as cached data
			refs := digests[entry.Digest]
			if len(refs) == 0 {
				digests[entry.Digest] = []*tocFile{active}
			} else {
				if len(paths) == 0 {
					// pre-cached from active the snapshot, this is a duplicated file inside the same TOC
					// do not track all duplicate refrences, they will only point to the first match
					active.CachedPaths, _ = active.CachedPaths.AddCachedPaths(ActiveSnap, digests[entry.Digest][0].Entry.Name)
				}
				digests[entry.Digest] = append(refs, active)
			}
		case "dir", "symlink", "hardlink", "char", "block", "fifo":
			structure = append(structure, entry)
		}
	}

	// Don't forget to queue the very last file in the TOC
	if active != nil {
		queueActiveFile(active)
	}

	log.Debugf("collected %d missing files", len(missing))
	log.Debugf("collected %d cached files", len(cached))

	return &processedTOC{
		missingFiles:    missing,
		cachedFiles:     cached,
		reverseCacheIdx: reverseIdx,
		digestsIdx:      digests,
		structure:       structure,
	}
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

// getDigest returns a map of snapshot keys containing the digest, each snapshot key points
// to a list of paths
func getDigest(bdb *bolt.DB, digest string) (cachedPaths, error) {
	paths := cachedPaths{}

	err := bdb.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(TopLevelBucket))
		if root == nil {
			return nil // Cache doesn't exist yet
		}

		locBucket := root.Bucket([]byte(LocBucket))
		if locBucket == nil {
			return nil
		}

		// Fetch the JSON array
		data := locBucket.Get([]byte(digest))
		if data != nil {
			if err := json.Unmarshal(data, &paths); err != nil {
				return fmt.Errorf("unmarshalling matched data: %w", err)
			}
		}
		return nil
	})

	return paths, err
}

func updateZstdCacheDB(log logger.Logger, db *bolt.DB, pTOC *processedTOC, snapshotKey string) error {
	return db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(TopLevelBucket))
		locBucket := root.Bucket([]byte(LocBucket))
		snapBucket := root.Bucket([]byte(SnapshotBucket))

		// TODO figure out if there is a better approach
		// We assume there will be a huge sequencial append
		root.FillPercent = 1.0
		locBucket.FillPercent = 1.0
		snapBucket.FillPercent = 1.0

		digestKeys := slices.Collect(maps.Keys(pTOC.digestsIdx))
		slices.Sort(digestKeys)

		log.Debugf("there are %d digests to update or create", len(digestKeys))

		snapDgsts := []string{}
		if data := snapBucket.Get([]byte(snapshotKey)); data != nil {
			err := json.Unmarshal(data, &snapDgsts)
			if err != nil {
				return fmt.Errorf("unmarshalling snapshots reverse index for %s: %w", snapshotKey, err)
			}
		}

		log.Debugf("snapshot %s has %d digests already cached", snapshotKey, len(snapDgsts))

		for _, digest := range digestKeys {
			tocFs := pTOC.digestsIdx[digest]
			newPaths := []string{}
			for _, tocF := range tocFs {
				newPaths = append(newPaths, tocF.Entry.Name)
			}

			paths := cachedPaths{}
			if data := locBucket.Get([]byte(digest)); data != nil {
				err := json.Unmarshal(data, &paths)
				if err != nil {
					return fmt.Errorf("unmarshalling cached digest (%s) before updating: %w", digest, err)
				}
			}
			paths, _ = paths.AddCachedPaths(snapshotKey, newPaths...)
			encodedPaths, _ := json.Marshal(paths)
			err := locBucket.Put([]byte(digest), encodedPaths)
			if err != nil {
				return fmt.Errorf("writing paths (%v) to the cache database: %w", newPaths, err)
			}

			if !slices.Contains(snapDgsts, digest) {
				snapDgsts = append(snapDgsts, digest)
			}
		}

		log.Debugf("setting %d digests to snapshot %s", len(snapDgsts), snapshotKey)

		encodedDigests, _ := json.Marshal(snapDgsts)
		err := snapBucket.Put([]byte(snapshotKey), encodedDigests)
		if err != nil {
			return fmt.Errorf("writing digests for snapshot %s: %w", snapshotKey, err)
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
