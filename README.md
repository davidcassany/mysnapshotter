# OCIStore

A daemonless OCI image storage library and CLI built on the [containerd v2](https://github.com/containerd/containerd)
stack — no containerd daemon required.

Born as a playground within the [Elemental Toolkit](https://github.com/rancher/elemental-toolkit) project, OCIStore
explores OCI image handling and, in particular, efficient extraction of `zstd:chunked` images into a single flattened
filesystem using delta fetches. It relies on Podman's `zstd:chunked` format for delta extraction.

## Build

```bash
make build
```

## Usage

```
ocistore [command] [flags]

Commands:
  commit         Commit an active snapshot as a new image
  delete         Delete an image
  extract        Pull and extract an image's flattened root tree to a directory
  import         Import an OCI archive
  list           List all images
  list-snapshots List all available snapshots
  mount          Mount an image to a target mountpoint
  pull           Pull a remote image into the local containerd store
  umount         Unmount a mountpoint
  unpack         Unpack an image

Global Flags:
      --debug             Enable debug logging
      --loglevel string   Set log output level
      --root string       Path for the local containerd store (default "/tmp/ocistore")
```

## zstd:chunked Extraction with Delta Fetches

The `extract` command pulls a remote image and extracts its flattened root filesystem:

```bash
ocistore extract IMAGE_REF DESTINATION [flags]

Flags:
      --delta           Only fetch files not present in the local cache (default true)
      --filedb string   Path for the local files database (default "/tmp/ocistore/files.db")
      --skip-tls        Skip TLS verification
```

When extracting a `zstd:chunked` image, OCIStore reads the Table of Contents from the compressed stream and compares
it against a local file database built from previous extractions. Only missing or changed files are downloaded —
files already cached are reused locally. This results in minimal network transfers when updating between image versions
or builds of the same image.

To build a `zstd:chunked` image, push with:

```bash
podman push --compression-format zstd:chunked <image-ref>
```

### Test Images

A pair of test images (`l1`, `l2`) are published via [openSUSE Build Service](https://build.opensuse.org/package/show/home:dcassany:Tumbleweed:containers:zstd:chunked/tumbleweed-test-containers):

```bash
# Extract "l1" — openSUSE Tumbleweed base with an extra layer
sudo ocistore --debug extract \
  registry.opensuse.org/home/dcassany/tumbleweed/containers/zstd/chunked/containers/opensuse/tumbleweed/chunked:l1 \
  ./extractions/l1

# Extract "l2" — built on top of "l1"; observe the delta download
sudo ocistore --debug extract \
  registry.opensuse.org/home/dcassany/tumbleweed/containers/zstd/chunked/containers/opensuse/tumbleweed/chunked:l2 \
  ./extractions/l2
```

Run `l1` first, then `l2` to see the delta fetch in action.

## License

See [LICENSE](LICENSE).
