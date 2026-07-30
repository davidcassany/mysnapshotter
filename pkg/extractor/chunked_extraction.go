/*
Copyright © 2026 SUSE LLC

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

package extractor

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/davidcassany/ocistore/pkg/chunked"
	"github.com/davidcassany/ocistore/pkg/filedb"
	"github.com/davidcassany/ocistore/pkg/logger"
	"github.com/davidcassany/ocistore/pkg/ocistore"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
)

func createStructuralNodes(log logger.Logger, structure []*chunked.FileMetadata, target string) (pending []*chunked.FileMetadata, err error) {
	var path string

	// sort paths to ensure we are starting from parent directories
	nodes := structure
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })

	log.Debugf("starting the creation of structural nodes. %d items", len(structure))

	for _, n := range nodes {
		path = filepath.Join(target, n.Name)
		goMode := os.FileMode(n.Mode)
		permBits := uint32(goMode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky))

		err = os.MkdirAll(filepath.Dir(path), os.FileMode(0700))
		if err != nil {
			return nil, fmt.Errorf("creating parent directories for path %q", path)
		}

		switch n.Type {
		case chunked.TypeReg:
			if n.Size != 0 {
				log.Warnf("non zero 'reg' entry type found (%s) with size %d, treating it as an empty file", n.Name, n.Size)
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
		case chunked.TypeDir:
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
			pending = append(pending, n)
			continue
		case chunked.TypeSymlink:
			linkname, err := turnSymlinkRelative(target, path, n.Linkname)
			if err != nil {
				return nil, fmt.Errorf("making relative a symlink %q with target %q", path, n.Linkname)
			}

			err = ensureSafePath(target, resolveSymlink(target, path, linkname))
			if err != nil {
				return nil, fmt.Errorf("sanitizing symlink %q with target %q", path, linkname)
			}

			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}

			err = os.Symlink(linkname, path)
			if err != nil {
				return nil, fmt.Errorf("creating symlink %s -> %s: %w", path, linkname, err)
			}
		case chunked.TypeLink:
			// apply hardlinks after applying cached and fetched files
			pending = append(pending, n)
			continue
		case chunked.TypeChar, chunked.TypeBlock:
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			mode := permBits | unix.S_IFCHR
			if n.Type == chunked.TypeBlock {
				mode = permBits | unix.S_IFBLK
			}
			dev := unix.Mkdev(uint32(n.Devmajor), uint32(n.Devminor))
			err := unix.Mknod(path, mode, int(dev))
			if err != nil {
				return nil, fmt.Errorf("creating char device %s: %w", path, err)
			}
		case chunked.TypeFifo:
			err = os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			err := unix.Mkfifo(path, permBits|unix.S_IFIFO)
			if err != nil {
				return nil, fmt.Errorf("creating the fifo file %s: %w", path, err)
			}
		case chunked.TypeChunk:
			log.Warn("'chunk' entry type found in structural nodes list, ignoring it")
			continue
		}
		err = applyMetadata(path, n)
		if err != nil {
			return nil, fmt.Errorf("failed applying GID, UID or Xattrs to %s: %w", path, err)
		}
	}

	return pending, nil
}

// applyMetadata sets the UID, GID, MTime and Extended Attributes on a created node
func applyMetadata(targetPath string, node *chunked.FileMetadata) error {
	// If targetPath is a symlink, Lchown changes the symlink itself.
	if err := os.Lchown(targetPath, node.UID, node.GID); err != nil {
		return fmt.Errorf("failed to apply Lchown to %s: %w", targetPath, err)
	}

	if node.ModTime != nil || node.AccessTime != nil {
		var ts [2]unix.Timespec
		atime := node.AccessTime
		mtime := node.ModTime

		// ATime or MTime fallback
		if mtime == nil {
			mtime = atime
		} else if atime == nil {
			atime = mtime
		}

		ts[0] = unix.NsecToTimespec(atime.UnixNano())
		ts[1] = unix.NsecToTimespec(mtime.UnixNano())

		// Do not follow symlinks
		err := unix.UtimesNanoAt(unix.AT_FDCWD, targetPath, ts[:], unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return fmt.Errorf("failed to apply timestamps to %s: %w", targetPath, err)
		}
	}

	for name, value := range node.Xattrs {
		xattr, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return fmt.Errorf("decoding extended attributes on file %q: %w", targetPath, err)
		}
		// The '0' flag means "create or replace".
		err = unix.Lsetxattr(targetPath, name, xattr, 0)
		if err != nil {
			// Note: Some xattrs requires privileges (e.g. CAP_SYS_ADMIN)
			return fmt.Errorf("failed to set xattr %s on %s: %w", name, targetPath, err)
		}
	}
	return nil
}

// resolveSymlink returns the target path rebased on baseDir
func resolveSymlink(baseDir, symlink, linkname string) string {
	symDir := filepath.Dir(filepath.Join(baseDir, symlink))

	if !filepath.IsAbs(linkname) {
		return filepath.Join(symDir, linkname)
	}

	return filepath.Join(baseDir, linkname)
}

// turnSymlinkRelative converts the target path of the symlink to a relative path for the given baseDir.
func turnSymlinkRelative(baseDir, symlink, linkname string) (string, error) {
	if filepath.IsAbs(linkname) {
		symDir := filepath.Dir(filepath.Join(baseDir, symlink))
		return filepath.Rel(symDir, filepath.Join(baseDir, linkname))
	}
	return linkname, nil
}

// ensureSafePath checks if the target path is lexically inside the base directory.
func ensureSafePath(baseDir, targetPath string) error {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of base dir: %v", err)
	}

	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of target: %v", err)
	}

	// Calculate the relative path from base to target
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return fmt.Errorf("failed to calculate relative path: %v", err)
	}

	// If the relative path starts with ".." or is exactly "..", it escapes the base dir
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return fmt.Errorf("path traversal detected: %s escapes %s", targetPath, baseDir)
	}

	return nil
}

func fetchAndApplyBlobRanges(ctx context.Context, log logger.Logger, fetcher ocistore.RangeFetcher, layerDesc ocispec.Descriptor, root string, ranges []*byteRangeGroup) (err error) {
	var currentStreamPos int64

	log.Debugf("starting to fecth coalesced ranges of the layer. %d items", len(ranges))

	for _, blobRange := range ranges {
		// fetch the range as a new compressed stream, the new compressed stream starts reading from position 0
		rc, err := ocistore.FetchRange(ctx, fetcher, layerDesc, blobRange.StartOffset, blobRange.Size)
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

func decompressFile(log logger.Logger, r io.Reader, zstdFile *tocFile, root string) (err error) {
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
	rangeReader := io.LimitReader(r, zstdFile.Range.Size)
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
		log.Debugf("Unexpected EOF when discarting bytes from uncompressed stream: %s", err.Error())
		return err
	}
	if err != nil {
		return fmt.Errorf("discarting bytes from uncompressed stream: %w", err)
	}

	for _, dup := range zstdFile.Duplicates {
		err = reflinkOrCopy(filepath.Join(root, dup.Entry.Name), path, dup.Entry)
		if err != nil {
			return fmt.Errorf("copying duplicates of %q: %w", path, err)
		}
	}

	return nil
}

func applyCachedFiles(log logger.Logger, cachedFiles []*tocFile, root string) error {
	log.Debugf("starting to feed extracted target with cached files. %d items", len(cachedFiles))

	for _, tFile := range cachedFiles {
		if len(tFile.CachedPaths) == 0 {
			log.Warnf("ignoring %q as it does not have cached paths", tFile.Entry.Name)
			continue
		}
		target := filepath.Join(root, tFile.Entry.Name)
		var err error
		for _, cPath := range tFile.CachedPaths {
			err = reflinkOrCopy(target, cPath, tFile.Entry)
			if err != nil {
				log.Warnf("error copying cached path %q to %q", cPath, target)
			}
		}
		if err != nil {
			return fmt.Errorf("failed extracting %q from cached paths: %w", target, err)
		}
	}

	return nil
}

func reflinkOrCopy(target, source string, entry *chunked.FileMetadata) (err error) {
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

func applyPendingNodes(log logger.Logger, pending []*chunked.FileMetadata, root string) error {
	var path string
	var err error

	// in reverse order to ensure we do not fall in the readonly trap
	slices.SortFunc(pending, func(a, b *chunked.FileMetadata) int {
		if a == nil || b == nil {
			return 0
		}
		return cmp.Compare(b.Name, a.Name)
	})

	log.Debugf("starting to apply directory permissions and hardlinks creation. %d items", len(pending))

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
			linkTarget := filepath.Join(root, e.Linkname)

			err = ensureSafePath(root, linkTarget)
			if err != nil {
				return fmt.Errorf("sanitazing hardlink: %w", err)
			}

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

func updateFileDB(db *filedb.DB, root string, pToc *processedTOC) error {
	files := make([]filedb.Entry, len(pToc.cachedFiles)+len(pToc.missingFiles))

	i := 0
	for _, t := range pToc.cachedFiles {
		files[i] = t
		i++
	}
	for _, t := range pToc.missingFiles {
		files[i] = t
		i++
	}

	return db.RecordAll(root, files)
}

func fetchAndApplyDeltaLayer(
	ctx context.Context, log logger.Logger, fetcher ocistore.RangeFetcher, db *filedb.DB,
	toc *chunked.TOC, layerDesc ocispec.Descriptor, destination string, seenPaths map[string]bool,
) error {

	pToc := processTOC(log, db, toc, seenPaths)

	p, err := createStructuralNodes(log, pToc.structure, destination)
	if err != nil {
		return fmt.Errorf("creating structural nodes: %w", err)
	}

	err = fetchAndApplyBlobRanges(ctx, log, fetcher, layerDesc, destination, groupMissingFiles(pToc.missingFiles))
	if err != nil {
		return fmt.Errorf("extracting specific missing ranges: %w", err)
	}

	err = applyCachedFiles(log, pToc.cachedFiles, destination)
	if err != nil {
		return fmt.Errorf("applying cached files: %w", err)
	}

	err = applyPendingNodes(log, p, destination)
	if err != nil {
		return fmt.Errorf("applying final metadata and links: %w", err)
	}

	err = updateFileDB(db, destination, pToc)
	if err != nil {
		return fmt.Errorf("updating cached files db: %w", err)
	}

	return nil
}
