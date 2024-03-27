# Testing

For now, unit tests and integration tests are supported on Linux. All tests run on CI for every
merge request. Code can't be merged unless builds and tests pass.

Unit tests ensure internal components are working fine. Unit tests *probably* also pass on MacOS.
```
cargo test
```
