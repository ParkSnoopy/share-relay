# share-relay architecture

This repository owns the Rust HTTP service, persistent opaque bundle queue, admission, retention, manager authorization and Docker image.
It does not own a consuming application's UI, VPN implementation, encryption format or profile mutations.
The public interface is specified in [PROTOCOL.md](./PROTOCOL.md).
The former NDJSON registration/message protocol is not supported.

## Configuration and distribution

[src/main.rs](./src/main.rs) uses Clap for CLI/environment parsing and Tokio for the listener, expiry worker and bounded graceful shutdown.
Explicit CLI values override process environment; dotenv files are not implicitly executed or loaded.
[.env.example](./.env.example) lists nonsecret deployment inputs: listener address, exact admitted hosts, private data directory and aggregate storage quota.
Empty admission configuration, subnet entries, malformed addresses and invalid quota fail closed.
Hostnames are re-resolved per request so replaced container addresses do not retain admission.
HTTP is carried by the deployment's protected transport, not relay-owned TLS.

The [Dockerfile](./Dockerfile) builds the locked Rust source in release mode and supplies its own executable as the entrypoint.
The default image user is UID/GID 65532 and the default data directory is private and owned by that user.
Deployments retaining a root-owned data mount must explicitly select the matching container UID without widening host file permissions.
The root filesystem may be read-only; only the private data mount needs writes.
The image carries queue-API label `io.parksnoopy.share-relay.api=1`.
No executable from a consuming application is required or mounted into this image.
The [publication workflow](./.github/workflows/publish-container.yml) publishes `ghcr.io/<lowercase-owner>/<lowercase-repo>` on each push to `main`.
It reads the package version from [Cargo.toml](./Cargo.toml) and publishes the `<version>` container tag without a `v` prefix.
If the version does not change, publication replaces the existing container tag with the new image.
After publication, it deletes any existing `v<version>` GitHub tag and creates that tag for the pushed commit.
It does not publish `latest` or major.minor container tags.

## Queue lifecycle

[src/lib.rs](./src/lib.rs) implements Axum request handling and a disk-backed queue with streamed transfers.
An exclusive process lock prevents two service processes from mutating one queue or cleaning each other's upload staging.
The data root contains private persistent manager authority, the lock file and a queue directory.
Each committed item has opaque bundle bytes and bounded JSON metadata under a random lowercase-hex ID.
Uploads reserve quota with a nonblocking semaphore, synchronize bytes/metadata and publish by directory rename; failed or cancelled uploads do not become visible.
Catalog access and publication use a separate short-lived mutex; downloads retain opened file handles independently of later expiry.
Expiry is enforced during inventory access and by the background worker.
Restart removes incomplete staging while preserving committed items and manager authority.
The wire and on-disk item fields remain compatible with the consuming client's existing HTTP contract.
Errors and operational logs must not contain payloads, manager authority or passwords.

## Verification boundary

Run `cargo fmt` with [rustfmt.toml](./rustfmt.toml), `cargo clippy --locked --all-targets -- -D warnings`, and `cargo test --locked` for development checks.
Deployment builds use `cargo build --release --locked`; tests use the non-release profile.
[tests/api.rs](./tests/api.rs) exercises real loopback HTTP for policy, source rejection, manager publication, retention, quotas, concurrent uploads, interrupted transfer cleanup, restart and expiry.
The executable's `probe ADDRESS` subcommand checks both `/policy` and `/items` with bounded responses, no bearer authority, no redirects and no proxy environment fallback.
A deployment must run this probe from each intended admitted source namespace, not only check an open TCP socket.
Native tests do not prove image execution, container volume permissions or a consuming application's routed VPN path.
Container verification must separately build the Dockerfile, exercise the image's own entrypoint/probe, and verify mounted data and authority across restart.