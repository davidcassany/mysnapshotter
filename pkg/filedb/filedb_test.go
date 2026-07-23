package filedb_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/davidcassany/ocistore/pkg/filedb"
)

func openTemp(t *testing.T) *filedb.DB {
	t.Helper()
	db, err := filedb.Open(filepath.Join(t.TempDir(), "filedb.bolt"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPathsForChecksum_unknown(t *testing.T) {
	db := openTemp(t)
	paths, err := db.PathsForChecksum("sha256:doesnotexist")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected empty slice, got %v", paths)
	}
}

func TestRecordAll_and_PathsForChecksum(t *testing.T) {
	db := openTemp(t)

	root := "/extractions/root1"
	entries := []filedb.Entry{
		{Digest: "sha256:aaa", RelPath: "usr/bin/foo"},
		{Digest: "sha256:bbb", RelPath: "usr/lib/bar.so"},
		{Digest: "", RelPath: "usr/share/doc"},   // directory — no digest, must be skipped
		{Digest: "sha256:aaa", RelPath: "usr/bin/foo2"}, // same digest, different path
	}

	if err := db.RecordAll(root, entries); err != nil {
		t.Fatalf("RecordAll: %v", err)
	}

	paths, err := db.PathsForChecksum("sha256:aaa")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(root, "usr/bin/foo"),
		filepath.Join(root, "usr/bin/foo2"),
	}
	slices.Sort(paths)
	slices.Sort(want)
	if !slices.Equal(paths, want) {
		t.Errorf("PathsForChecksum(aaa): got %v, want %v", paths, want)
	}

	// digest with no paths in the DB
	paths, err = db.PathsForChecksum("sha256:zzz")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Errorf("expected no paths for unknown digest, got %v", paths)
	}
}

func TestRemoveRoot_cleansUpOrphanDigests(t *testing.T) {
	db := openTemp(t)

	root1 := "/extractions/root1"
	root2 := "/extractions/root2"
	sharedDigest := "sha256:shared"
	onlyRoot1 := "sha256:only1"

	if err := db.RecordAll(root1, []filedb.Entry{
		{Digest: sharedDigest, RelPath: "usr/bin/foo"},
		{Digest: onlyRoot1, RelPath: "usr/lib/private.so"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAll(root2, []filedb.Entry{
		{Digest: sharedDigest, RelPath: "usr/bin/foo"},
	}); err != nil {
		t.Fatal(err)
	}

	// Before removal: sharedDigest has two paths.
	paths, _ := db.PathsForChecksum(sharedDigest)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths for sharedDigest before removal, got %v", paths)
	}

	if err := db.RemoveRoot(root1); err != nil {
		t.Fatalf("RemoveRoot: %v", err)
	}

	// sharedDigest still has root2's path.
	paths, err := db.PathsForChecksum(sharedDigest)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root2, "usr/bin/foo")}
	if !slices.Equal(paths, want) {
		t.Errorf("PathsForChecksum(shared) after removing root1: got %v, want %v", paths, want)
	}

	// onlyRoot1 digest must be gone entirely.
	paths, err = db.PathsForChecksum(onlyRoot1)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Errorf("expected onlyRoot1 digest to be GC'd, got %v", paths)
	}
}

func TestRemoveRoot_nonexistentIsNoop(t *testing.T) {
	db := openTemp(t)
	if err := db.RemoveRoot("/does/not/exist"); err != nil {
		t.Fatalf("RemoveRoot on unknown root: %v", err)
	}
}

func TestRemoveRoot_allRoots_clearsAllDigests(t *testing.T) {
	db := openTemp(t)

	root1 := "/extractions/root1"
	root2 := "/extractions/root2"
	digest := "sha256:abc"

	db.RecordAll(root1, []filedb.Entry{{Digest: digest, RelPath: "bin/x"}})
	db.RecordAll(root2, []filedb.Entry{{Digest: digest, RelPath: "bin/x"}})

	db.RemoveRoot(root1)
	db.RemoveRoot(root2)

	paths, err := db.PathsForChecksum(digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Errorf("expected digest to be fully GC'd, got %v", paths)
	}
}
