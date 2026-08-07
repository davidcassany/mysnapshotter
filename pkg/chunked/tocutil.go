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

package chunked

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// OCI layer annotation keys written by zstd:chunked-aware tools.
const (
	// ManifestChecksumKey holds the sha256 digest of the compressed TOC blob
	// in "sha256:<hex>" format.
	ManifestChecksumKey = "io.github.containers.zstd-chunked.manifest-checksum"

	// ManifestInfoKey encodes offset, compressed length, uncompressed length,
	// and manifest type as four colon-separated decimal integers:
	//   "<offset>:<compressedLen>:<uncompressedLen>:<type>"
	// The type must be 1 (ManifestTypeCRFS).
	ManifestInfoKey = "io.github.containers.zstd-chunked.manifest-position"
)

const (
	// FooterSize is the size of the binary footer payload in bytes.
	FooterSize = 64

	// FooterFrameSize is the total number of bytes to fetch from the END of
	// the blob to obtain the self-describing binary footer.
	// It is an 8-byte zstd skippable-frame header followed by FooterSize bytes.
	FooterFrameSize = FooterSize + 8

	// MaxTOCSize is the largest TOC (compressed or uncompressed) we will read
	// into memory; acts as a DoS safeguard.
	MaxTOCSize = 150 << 20 // 150 MiB
)

// Entry type constants — value of FileMetadata.Type.
const (
	TypeReg     = "reg"
	TypeLink    = "hardlink"
	TypeChar    = "char"
	TypeBlock   = "block"
	TypeDir     = "dir"
	TypeFifo    = "fifo"
	TypeSymlink = "symlink"
	// TypeChunk is used for the continuation entries of a large file that
	// has been split into rolling-checksum chunks.  The initial entry for
	// the file has TypeReg; each following TypeChunk entry holds the
	// location (Offset/EndOffset) of one chunk.
	TypeChunk = "chunk"
)

// ChunkType constants — value of FileMetadata.ChunkType.
const (
	ChunkTypeData  = ""      // normal compressed data in the blob
	ChunkTypeZeros = "zeros" // a run of zero bytes; no bytes in the blob
)

var (
	zstdSkippableFrameMagic = []byte{0x50, 0x2a, 0x4d, 0x18}
	zstdChunkedFrameMagic   = []byte{0x47, 0x4e, 0x55, 0x6c, 0x49, 0x6e, 0x55, 0x78} // "GNUlInUx"
)

// TOC is the Table of Contents of a zstd:chunked layer.
type TOC struct {
	Version        int            `json:"version"`
	Entries        []FileMetadata `json:"entries"`
	TarSplitDigest string         `json:"tarSplitDigest,omitempty"`
}

// FileMetadata describes one file (or sub-chunk of a file) stored in the
// layer.  Offset and EndOffset are the key fields for selective fetching:
// they give the half-open byte range [Offset, EndOffset) within the
// compressed layer blob that holds this entry's data.
type FileMetadata struct {
	// Standard file metadata.
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Linkname   string            `json:"linkName,omitempty"`
	Mode       int64             `json:"mode,omitempty"`
	Size       int64             `json:"size,omitempty"`
	UID        int               `json:"uid,omitempty"`
	GID        int               `json:"gid,omitempty"`
	ModTime    *time.Time        `json:"modtime,omitempty"`
	AccessTime *time.Time        `json:"accesstime,omitempty"`
	ChangeTime *time.Time        `json:"changetime,omitempty"`
	Devmajor   int64             `json:"devMajor,omitempty"`
	Devminor   int64             `json:"devMinor,omitempty"`
	Xattrs     map[string]string `json:"xattrs,omitempty"` // values are base64-encoded

	// sha256 digest of the full file contents ("sha256:<hex>"); empty for
	// zero-length files.
	Digest string `json:"digest,omitempty"`

	// Offset and EndOffset define the half-open byte range [Offset, EndOffset)
	// of this entry's data within the compressed layer blob.  Use these to
	// issue a range request for exactly the bytes you need.
	Offset    int64 `json:"offset,omitempty"`
	EndOffset int64 `json:"endOffset,omitempty"`

	// Chunk fields — populated when a large file is split across multiple
	// rolling-checksum chunks.  Present on both the initial TypeReg entry and
	// every subsequent TypeChunk entry that belongs to the same file.
	ChunkSize   int64  `json:"chunkSize,omitempty"`
	ChunkOffset int64  `json:"chunkOffset,omitempty"` // logical offset within the file
	ChunkDigest string `json:"chunkDigest,omitempty"`
	ChunkType   string `json:"chunkType,omitempty"` // "" (data) or "zeros"
}

// TOCLocation describes where the compressed TOC payload lives within the
// blob.  Pass Offset and LengthCompressed to your range-fetch logic.
type TOCLocation struct {
	// Offset is the absolute byte offset of the first compressed TOC byte
	// within the blob.  This is the compressed payload itself — it does NOT
	// include the surrounding 8-byte zstd skippable-frame header.
	Offset uint64

	// LengthCompressed is the number of bytes to fetch starting at Offset.
	LengthCompressed uint64

	// LengthUncompressed is the expected size after decompression.  Used only
	// to pre-allocate a buffer; may be 0 if unknown (ParseFooterFrame always
	// fills it; ParseAnnotations fills it from the annotation).
	LengthUncompressed uint64

	// Digest is the expected sha256 digest of the compressed bytes in
	// "sha256:<hex>" format.  Set by ParseAnnotations when ManifestChecksumKey
	// is present.  Leave empty to skip integrity verification in ParseTOC.
	Digest string
}

// ParseAnnotations extracts the TOC location and integrity digest from OCI
// layer descriptor annotations produced by zstd:chunked-aware tooling.
//
// It reads ManifestInfoKey (required) and ManifestChecksumKey (optional but
// strongly recommended — used for integrity verification in ParseTOC).
func ParseAnnotations(annotations map[string]string) (*TOCLocation, error) {
	info, ok := annotations[ManifestInfoKey]
	if !ok {
		return nil, fmt.Errorf("annotation %q absent — layer may not be zstd:chunked", ManifestInfoKey)
	}

	parts := strings.SplitN(info, ":", 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("annotation %q: expected 4 colon-separated fields, got %q", ManifestInfoKey, info)
	}
	parseU64 := func(s, field string) (uint64, error) {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("annotation %q: parsing %s: %w", ManifestInfoKey, field, err)
		}
		return v, nil
	}

	offset, err := parseU64(parts[0], "offset")
	if err != nil {
		return nil, err
	}
	compLen, err := parseU64(parts[1], "compressed length")
	if err != nil {
		return nil, err
	}
	uncompLen, err := parseU64(parts[2], "uncompressed length")
	if err != nil {
		return nil, err
	}
	manifestType, err := parseU64(parts[3], "manifest type")
	if err != nil {
		return nil, err
	}
	if manifestType != 1 {
		return nil, fmt.Errorf("annotation %q: unsupported manifest type %d (expected 1)", ManifestInfoKey, manifestType)
	}

	loc := &TOCLocation{
		Offset:             offset,
		LengthCompressed:   compLen,
		LengthUncompressed: uncompLen,
	}
	if cs := annotations[ManifestChecksumKey]; cs != "" {
		loc.Digest = cs
	}
	return loc, nil
}

// ParseFooterFrame reads the 72-byte skippable frame from the very end of
// a zstd:chunked blob and returns the TOC location.
//
// r must supply exactly FooterFrameSize (72) bytes: the 8-byte skippable-
// frame header followed by the 64-byte binary payload.  Fetch this range
// with:
//
//	FetchRange(blobURL, blobSize-FooterFrameSize, FooterFrameSize)
//
// Note: the Digest field of the returned location is always empty because
// the binary footer does not include the TOC digest.  If you also have the
// OCI manifest annotations, call ParseAnnotations instead (it fills Digest),
// or set loc.Digest manually from ManifestChecksumKey before calling ParseTOC.
func ParseFooterFrame(r io.Reader) (*TOCLocation, error) {
	buf := make([]byte, FooterFrameSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("reading footer frame: %w", err)
	}

	// Validate the surrounding skippable-frame header.
	if !bytes.Equal(buf[:4], zstdSkippableFrameMagic) {
		return nil, errors.New("not a zstd skippable frame: wrong magic at end of blob")
	}
	framePayloadLen := binary.LittleEndian.Uint32(buf[4:8])
	if framePayloadLen != FooterSize {
		return nil, fmt.Errorf("footer frame payload size %d != expected %d", framePayloadLen, FooterSize)
	}

	payload := buf[8:] // 64 bytes

	// The last 8 bytes of the payload are the zstd:chunked magic.
	if !bytes.Equal(payload[56:64], zstdChunkedFrameMagic) {
		return nil, errors.New("invalid zstd:chunked magic — blob is not a zstd:chunked layer")
	}

	// Binary layout (all little-endian uint64, 8 bytes each):
	//   [0 ] offset of compressed TOC payload
	//   [8 ] compressed TOC length
	//   [16] uncompressed TOC length
	//   [24] manifest type (must be 1)
	//   [32] offset of compressed tar-split payload
	//   [40] compressed tar-split length
	//   [48] uncompressed tar-split length
	//   [56] magic ("GNUlInUx")
	manifestType := binary.LittleEndian.Uint64(payload[24:32])
	if manifestType != 1 {
		return nil, fmt.Errorf("unsupported manifest type %d (expected 1)", manifestType)
	}

	return &TOCLocation{
		Offset:             binary.LittleEndian.Uint64(payload[0:8]),
		LengthCompressed:   binary.LittleEndian.Uint64(payload[8:16]),
		LengthUncompressed: binary.LittleEndian.Uint64(payload[16:24]),
	}, nil
}

// ParseTOC reads the compressed TOC bytes from r, optionally verifies their
// integrity, decompresses them, and returns the parsed TOC.
//
// r must supply exactly loc.LengthCompressed bytes — the raw compressed
// payload, without any skippable-frame header.  The caller is responsible
// for closing r; ParseTOC drains it fully.
//
// If loc.Digest is set (format: "sha256:<hex>"), the compressed bytes are
// verified against that digest before decompression; ParseTOC returns an
// error on mismatch.  Skipping verification is not recommended for
// security-sensitive use.
func ParseTOC(r io.Reader, loc *TOCLocation) (*TOC, error) {
	if loc.LengthCompressed > MaxTOCSize {
		return nil, fmt.Errorf("compressed TOC too large (%d bytes); refusing to read", loc.LengthCompressed)
	}
	if loc.LengthUncompressed > MaxTOCSize {
		return nil, fmt.Errorf("uncompressed TOC too large (%d bytes); refusing to decompress", loc.LengthUncompressed)
	}

	compressed := make([]byte, loc.LengthCompressed)
	if _, err := io.ReadFull(r, compressed); err != nil {
		return nil, fmt.Errorf("reading compressed TOC: %w", err)
	}

	if loc.Digest != "" {
		if err := verifySHA256(compressed, loc.Digest); err != nil {
			return nil, fmt.Errorf("TOC integrity check: %w", err)
		}
	}

	capacity := loc.LengthUncompressed
	if capacity == 0 {
		capacity = uint64(len(compressed)) * 4
	}

	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("creating zstd decoder: %w", err)
	}
	defer dec.Close()

	decompressed, err := dec.DecodeAll(compressed, make([]byte, 0, capacity))
	if err != nil {
		return nil, fmt.Errorf("decompressing TOC: %w", err)
	}

	var toc TOC
	if err := json.Unmarshal(decompressed, &toc); err != nil {
		return nil, fmt.Errorf("parsing TOC JSON: %w", err)
	}
	return &toc, nil
}

// verifySHA256 checks that sha256(data) == the digest encoded in "sha256:<hex>".
func verifySHA256(data []byte, expected string) error {
	hexDigest, ok := strings.CutPrefix(expected, "sha256:")
	if !ok {
		return fmt.Errorf("unsupported digest format %q (only sha256 is supported)", expected)
	}
	expectedBytes, err := hex.DecodeString(hexDigest)
	if err != nil {
		return fmt.Errorf("invalid hex in digest %q: %w", expected, err)
	}
	got := sha256.Sum256(data)
	if !bytes.Equal(got[:], expectedBytes) {
		return fmt.Errorf("digest mismatch: expected sha256:%x, got sha256:%x", expectedBytes, got)
	}
	return nil
}
