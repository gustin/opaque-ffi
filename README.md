
## Building

Requires nightly rust for some OPAQUE dependencies (inline assembly, etc).


## Dependencies

### RocksDB

This should be able to be fully embedded.

    brew install rocksdb

## Clippy

Will attempt to cleanup certain issues:

    cargo fix -Z unstable-options --clippy

## Copyright

    go get -u github.com/fbiville/headache/cmd/headache
    headache

