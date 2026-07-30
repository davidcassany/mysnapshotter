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

package extractor

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/platforms"
	"github.com/davidcassany/ocistore/pkg/filedb"
	"github.com/davidcassany/ocistore/pkg/logger"
	"github.com/davidcassany/ocistore/pkg/ocistore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const DefaultDBPath = ocistore.DefaultRoot + "/files.db"

type Extractor struct {
	ctx        context.Context
	log        logger.Logger
	platform   platforms.MatchComparer
	fileDbPath string
}

type ExtractorOpt func(e *Extractor)

func WithDBPath(path string) ExtractorOpt {
	return func(e *Extractor) {
		e.fileDbPath = path
	}
}

func NewExtractor(ctx context.Context, log logger.Logger, opts ...ExtractorOpt) *Extractor {
	e := &Extractor{
		log:        log,
		platform:   platforms.DefaultStrict(),
		ctx:        ctx,
		fileDbPath: DefaultDBPath,
	}

	for _, o := range opts {
		o(e)
	}

	return e
}

type metadata struct {
	mfst *ocispec.Manifest
	conf *ocispec.Image
}

// Hardlink tracks links that must be applied after all layers are extracted
type Hardlink struct {
	OldPath string
	NewPath string
}

func (e Extractor) ExtractImage(imageRef, destination, platformRef string, local bool, verify bool) (_ string, err error) {
	destination, err = filepath.Abs(destination)
	if err != nil {
		return "", fmt.Errorf("cannot set destination %q as an absolute path: %w", destination, err)
	}

	err = os.MkdirAll(destination, 0755)
	if err != nil {
		return "", fmt.Errorf("creating destination directory: %w", err)
	}

	e.log.Debugf("Extracting image to %s", destination)

	// TODO check if it handles authorization
	resolver := ocistore.SetupOCIRegistryResolver(verify, nil)

	name, desc, err := resolver.Resolve(e.ctx, imageRef)
	if err != nil {
		e.log.Errorf("failed resolving image reference into a name and OCI descriptor: %v", err)
		return "", err
	}

	fetcher, err := resolver.Fetcher(e.ctx, name)
	if err != nil {
		return "", fmt.Errorf("initiating fetcher for image %s: %w", name, err)
	}

	var (
		handler images.Handler
		imgMeta metadata
	)

	handler = images.Handlers(images.FilterPlatforms(
		fetchManifestAndConfig(e.log, fetcher, &imgMeta),
		e.platform),
	)

	if err := images.Dispatch(e.ctx, handler, nil, desc); err != nil {
		return "", fmt.Errorf("failed on image dispatch: %w", err)
	}

	if imgMeta.mfst == nil || imgMeta.conf == nil {
		return "", fmt.Errorf("failed to find manifest and image config")
	}

	digest := imgMeta.mfst.Config.Digest.String()

	seenPaths := map[string]bool{}

	db, err := filedb.Open(e.fileDbPath)
	if err != nil {
		return "", fmt.Errorf("creating file database: %w", err)
	}

	for _, layerDesc := range slices.Backward(imgMeta.mfst.Layers) {
		toc, err := ocistore.FetchToC(e.ctx, fetcher, layerDesc)
		if err != nil {
			e.log.Errorf("failed to extract toc: %s", err.Error())
		} else {
			e.log.Infof("ToC successfully fetched and parsed! Entries: %d", len(toc.Entries))
		}

		if toc == nil {
			err = fetchAndApplyLayer(e.ctx, fetcher, layerDesc, destination, seenPaths)
			if err != nil {
				return "", err
			}
		} else {
			defer func() {
				if err != nil {
					err = errors.Join(err, db.RemoveRoot(destination))
				}
			}()

			err = fetchAndApplyDeltaLayer(e.ctx, e.log, fetcher, db, toc, layerDesc, destination, seenPaths)
			if err != nil {
				return "", err
			}
		}
	}

	return digest, nil
}

func fetchAndApplyLayer(ctx context.Context, fetcher remotes.Fetcher, layer ocispec.Descriptor, destination string, seenPaths map[string]bool) error {
	rc, err := fetcher.Fetch(ctx, layer)
	if err != nil {
		return fmt.Errorf("failed to fetch layer %s: %w", layer.Digest, err)
	}

	uncompressedStream, err := compression.DecompressStream(rc)
	if err != nil {
		return err
	}

	hardlinks := []Hardlink{}
	opts := []archive.ApplyOpt{
		archive.WithFilter(filterFunc(destination, seenPaths, hardlinks)),
		archive.WithConvertWhiteout(whiteoutFunc(seenPaths)),
	}
	_, err = archive.Apply(ctx, destination, uncompressedStream, opts...)
	uErr := uncompressedStream.Close()
	if err == nil && uErr != nil {
		err = uErr
	}
	cErr := rc.Close()
	if err == nil && cErr != nil {
		err = cErr
	}
	if err != nil {
		return fmt.Errorf("failed to apply layer %s: %w", layer.Digest, err)
	}

	for _, hl := range hardlinks {
		if err := os.MkdirAll(filepath.Dir(hl.NewPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory for hardlink: %w", err)
		}
		if err := os.Link(hl.OldPath, hl.NewPath); err != nil {
			return fmt.Errorf("failed to create hardlink %s -> %s: %w", hl.OldPath, hl.NewPath, err)
		}
	}

	return nil
}

// whiteoutFunc tracks whiteout files and opaque paths as seen, so they are not extracted
func whiteoutFunc(seenPaths map[string]bool) func(hdr *tar.Header, path string) (bool, error) {
	return func(hdr *tar.Header, path string) (bool, error) {
		relPath := filepath.Clean(hdr.Name)
		baseName := filepath.Base(relPath)
		dirName := filepath.Dir(relPath)

		if baseName == ".wh..wh..opq" {
			seenPaths[dirName] = true
		} else {
			actualFile := filepath.Join(dirName, strings.TrimPrefix(baseName, ".wh."))
			seenPaths[actualFile] = hdr.Typeflag != tar.TypeDir
		}

		// return false so neither the `.wh.` file is written nor deletion occurs
		return false, nil
	}
}

func isParentWhiteout(seenPaths map[string]bool, path string) bool {
	dir := filepath.Dir(path)
	for dir != "." && dir != "/" && dir != "" {
		if val, ok := seenPaths[dir]; val && ok {
			return true
		}
		dir = filepath.Dir(dir)
	}
	return false
}

// filterFunc prevents to extract files that are included in the extracted cache and feeds the extracted cache with files being extracted.
// It also intercepts all hardlinks for later processing
func filterFunc(destination string, seenPaths map[string]bool, hardlinks []Hardlink) func(hdr *tar.Header) (bool, error) {
	return func(hdr *tar.Header) (bool, error) {
		relPath := filepath.Clean(hdr.Name)
		if relPath == "." || relPath == "/" {
			return true, nil
		}

		// allow whiteouts to pass through to the ConvertWhiteout logic
		baseName := filepath.Base(relPath)
		if strings.HasPrefix(baseName, ".wh.") {
			return true, nil
		}

		// omit if previously seen from an upper layer
		if seenPaths[relPath] || isParentWhiteout(seenPaths, relPath) {
			return false, nil
		}

		// mark as seen for subsequent lower layers
		seenPaths[relPath] = hdr.Typeflag != tar.TypeDir

		// intercept hardlinks for deferred processing
		if hdr.Typeflag == tar.TypeLink {
			oldpath := filepath.Join(destination, hdr.Linkname)
			if !strings.HasPrefix(oldpath, destination+string(filepath.Separator)) {
				return false, fmt.Errorf("illegal hardlink target escapes destination directory: %s", hdr.Linkname)
			}
			hardlinks = append(hardlinks, Hardlink{
				NewPath: filepath.Join(destination, relPath),
				OldPath: oldpath,
			})
			return false, nil // Skip native extraction
		}

		// Extract all other unseen files normally
		return true, nil
	}
}

func fetchManifestAndConfig(log logger.Logger, fetcher remotes.Fetcher, metadata *metadata) images.HandlerFunc {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		switch {
		case images.IsDockerType(desc.MediaType):
			return nil, fmt.Errorf("%s media type not supported", desc.MediaType)
		case images.IsIndexType(desc.MediaType):
			var index ocispec.Index
			metadataBytes, err := ocistore.FetchMetadata(ctx, fetcher, desc)
			if err != nil {
				return nil, fmt.Errorf("failed fetching index: %w", err)
			}
			if err := json.Unmarshal(metadataBytes, &index); err != nil {
				return nil, fmt.Errorf("unmarshalling index error: %w", err)
			}
			log.Debugf("Fetched index manifest with digest: %s", desc.Digest)
			return append([]ocispec.Descriptor{}, index.Manifests...), nil
		case images.IsManifestType(desc.MediaType):
			if metadata.mfst != nil {
				return nil, fmt.Errorf("manifest already defined, there can only be one")
			}
			metadataBytes, err := ocistore.FetchMetadata(ctx, fetcher, desc)
			if err != nil {
				return nil, fmt.Errorf("failed fetching manifest: %w", err)
			}

			var manifest ocispec.Manifest
			if err := json.Unmarshal(metadataBytes, &manifest); err != nil {
				return nil, fmt.Errorf("unmarshalling manifest error: %w", err)
			}
			metadata.mfst = &manifest

			log.Debugf("Fetched image manifest with digest: %s", desc.Digest)
			return append([]ocispec.Descriptor{manifest.Config}, manifest.Layers...), nil
		case images.IsConfigType(desc.MediaType):
			if metadata.conf != nil {
				return nil, fmt.Errorf("config is not zero, there can only be one")
			}

			metadataBytes, err := ocistore.FetchMetadata(ctx, fetcher, desc)
			if err != nil {
				return nil, fmt.Errorf("failed fetching manifest: %w", err)
			}

			var config ocispec.Image
			if err := json.Unmarshal(metadataBytes, &config); err != nil {
				return nil, fmt.Errorf("unmarshalling config error: %w", err)
			}

			metadata.conf = &config
			log.Debugf("Fetched image config with digest: %s", desc.Digest)
			return nil, nil
		case images.IsLayerType(desc.MediaType):
			log.Debugf("encountered a layer type, not fetching it")
		default:
			log.Debugf("encountered unknown type %v; children may not be fetched", desc.MediaType)
		}
		return nil, nil
	}
}
