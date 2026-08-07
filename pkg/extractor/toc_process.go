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
	"path/filepath"
	"sort"

	"github.com/davidcassany/ocistore/pkg/chunked"
	"github.com/davidcassany/ocistore/pkg/filedb"
	"github.com/davidcassany/ocistore/pkg/logger"
)

// TODO consider if there could be separate types for missing and cached files
// tocFile represents an entire file, aggregating the bytes range of the initial
// reg entry and any subsequent chunk entries.
type tocFile struct {
	// Entry is the file metadata of the represented file
	Entry *chunked.FileMetadata

	// CachedPaths are the already extracted paths where the file contents can be found
	CachedPaths []string

	// Duplicates slice lists duplicated tocFiles within the layer itself
	Duplicates []*tocFile

	// Range represents the full byte range of the file within the compressed layer
	Range *byteRange
}

type byteRange struct {
	Offset int64
	Size   int64
}

type processedTOC struct {
	// missing files listed by ascending byte range, these are meant to be fetched from the remote layer
	missingFiles []*tocFile

	// already cached files listed by ascending byte range, these are meant to be found in the system already
	cachedFiles []*tocFile

	// these are structural nodes manually created (dirs, symlinks, hardlinks, devices, etc.)
	structure []*chunked.FileMetadata
}

// byteRangeGroup represents a coalesced HTTP Range request for one or more files
type byteRangeGroup struct {
	StartOffset int64
	Size        int64
	Files       []*tocFile
}

func (t *tocFile) Digest() string {
	if t.Entry != nil {
		return t.Entry.Digest
	}
	return ""
}

func (t *tocFile) RelPaths() []string {
	var paths []string
	if t.Entry == nil {
		return paths
	}
	paths = make([]string, len(t.Duplicates)+1)
	paths[0] = t.Entry.Name

	for i, dup := range t.Duplicates {
		if dup != nil {
			paths[i+1] = dup.Entry.Name
		}
	}
	return paths
}

func processTOC(log logger.Logger, bdb *filedb.DB, toc *chunked.TOC, lCtx *layerCtx) *processedTOC {
	//var active *tocFile
	var missing, cached []*tocFile
	var structure []*chunked.FileMetadata
	digests := map[string][]*tocFile{}

	// TODO probably it can be assumed this is already the case, it doesn't make
	// sense the entry list if they are not sorted by range
	sort.Slice(toc.Entries, func(i, j int) bool {
		return toc.Entries[i].Offset < toc.Entries[j].Offset
	})

	log.Debugf("starting to split Table of Contents between misses, cached and structural files")

	for _, entry := range toc.Entries {
		// if it's a chunk ignore it, the associated reg already has the full offset
		if entry.Type == chunked.TypeChunk {
			continue
		}

		relPath := filepath.Clean(entry.Name)

		// filter whiteouts
		if filterWhiteout(lCtx, relPath) || isParentWhiteout(lCtx.whiteouts, relPath) {
			continue
		}

		// omit if previously seen from an upper layer
		if lCtx.seenPaths[relPath] {
			continue
		}

		// Ensure we won't extract this file again on follow up layers
		lCtx.seenPaths[relPath] = true

		var tf *tocFile

		// handle the new entry based on its type
		switch entry.Type {
		case chunked.TypeReg:
			if entry.Size == 0 || entry.Digest == "" {
				structure = append(structure, &entry)
				continue
			}
			// query filedb using the whole file digest
			paths, err := bdb.PathsForChecksum(entry.Digest)
			if err != nil {
				log.Warnf("error getting cached paths for digest %s, considering it a cache miss. err: %s", entry.Digest, err.Error())
			}

			// The 'reg' entry contains the payload coordinates
			tf = &tocFile{
				Entry:       &entry,
				CachedPaths: paths,
				Range: &byteRange{
					Offset: entry.Offset,
					Size:   entry.EndOffset - entry.Offset,
				},
			}

			// consider duplicated missing digests as cached data
			refs := digests[entry.Digest]
			if len(refs) == 0 {
				digests[entry.Digest] = []*tocFile{tf}
			} else {
				if len(paths) == 0 {
					// pre-cached from current layer, this is a duplicated file inside the same TOC
					// do not track all duplicate refrences, they will only point to the first match
					tf.Duplicates = refs
					for _, e := range refs {
						e.Duplicates = append(e.Duplicates, tf)
					}
				}
				digests[entry.Digest] = append(refs, tf)
			}
		case chunked.TypeDir, chunked.TypeSymlink, chunked.TypeChar, chunked.TypeBlock, chunked.TypeFifo, chunked.TypeLink:
			structure = append(structure, &entry)
		}

		if tf != nil {
			if len(tf.CachedPaths) > 0 {
				// Cache Hit: The file is already available in disk
				cached = append(cached, tf)
			} else if len(tf.Duplicates) == 0 {
				// Cache Miss: Queue the range chunk for download.
				// We are not adding to misses any duplicated only first apprearence is added
				missing = append(missing, tf)
			}
		}
	}

	// Ensure opaques are honored in any follow up layer
	lCtx.applyOpaques()

	log.Debugf("collected %d missing files", len(missing))
	log.Debugf("collected %d cached files", len(cached))
	log.Debugf("collected %d structural nodes", len(structure))

	return &processedTOC{
		missingFiles: missing,
		cachedFiles:  cached,
		structure:    structure,
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
				Size:        miss.Range.Size,
				Files:       []*tocFile{miss},
			}
			continue
		}

		// Calculate the physical byte gap between the current group and the next chunk
		gap := miss.Range.Offset - (current.StartOffset + current.Size)

		if gap >= 0 && gap <= gapThreshold {
			// The gap is small enough. Merge this chunk into the current HTTP request.
			current.Size = miss.Range.Offset + miss.Range.Size - current.StartOffset
			current.Files = append(current.Files, miss)
			continue
		}
		// The gap is too large. Save the current group and start a new one.
		groups = append(groups, current)
		current = &byteRangeGroup{
			StartOffset: miss.Range.Offset,
			Size:        miss.Range.Size,
			Files:       []*tocFile{miss},
		}
	}

	if current != nil {
		groups = append(groups, current)
	}

	return groups
}
