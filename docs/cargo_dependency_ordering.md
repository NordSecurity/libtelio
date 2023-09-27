# Cargo dependency ordering

To make out Cargo files more predictable and easier to read, please follow these guidelines.

## Section ordering

1. features
2. dependencies
3. dev-dependencies
4. build-dependencies
5. Platfrom-specific dependencies (within each of these, follow points 1-4)

## Dependency grouping

In each of the sections mentioned in the previous part, the dependencies should be ordered as such:

1. Cargo dependencies that are not marked as workspace dependencies
2. Workspace dependencies
3. Git dependencies
4. Internal crates

## Other considerations

Each group of dependencies after following the above points should have its dependencies ordered in alphabetical order.

# Example

```toml
[features]
test-util = []

[dependencies]
cfg-if = "1.0.0"
num_cpus = "1.15.0"

anyhow.workspace = true
futures.workspace = true
modifier.workspace = true
serde.workspace = true
uuid.workspace = true

trust-dns-client = { git = "https://github.com/NordSecurity/trust-dns.git", tag = "v2.0.0" }
trust-dns-server = { git = "https://github.com/NordSecurity/trust-dns.git", tag = "v2.0.0", features = ["resolver"] }

telio-crypto.workspace = true
telio-firewall.workspace = true
telio-sockets.workspace = true
telio-wg.workspace = true

[dev-dependencies]
dns-parser = "0.8.0"

mockall.workspace = true

[build-dependencies]
cc = "1"

[target.'cfg(target_os = "android")'.dependencies]
rupnp = { version = "1.1.0", default-features = false }

[target.'cfg(not(target_os = "android"))'.dependencies]
rupnp.workspace = true

[target.'cfg(windows)'.dependencies]
winapi = { workspace = true, features = ["ntdef", "winerror"] }

[target.'cfg(windows)'.build-dependencies]
winres = "0.1"
```
