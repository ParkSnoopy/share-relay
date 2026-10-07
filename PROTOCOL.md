# Share HTTP protocol

The Rust service implements an opaque persistent bundle queue, not registration, presence or message broadcasting.
Implementation: [src/lib.rs](./src/lib.rs); lifecycle and distribution: [LLM_WIKI.md](./LLM_WIKI.md).
HTTP runs inside the deployment's protected transport; the relay does not terminate TLS or interpret encrypted contents.

## Admission

Every endpoint requires either an exact configured source IP/DNS match or valid manager bearer authority.
DNS is re-resolved per request under a bounded deadline; forwarded headers, reverse DNS and subnet claims are not trusted.
An absent or empty allowed-host configuration fails startup.
A forged bearer does not promote an admitted ordinary peer; an unadmitted peer receives `403`.
Manager authority persists independently of clients and is not returned by the API.

## Endpoints

| Method and path | Request | Success |
| --- | --- | --- |
| `GET /policy` | No body | `200`, JSON `manager` boolean and `userRetentionHours` integer |
| `GET /items` | No body | `200`, JSON array of unexpired items, newest creation first, ID ascending for ties |
| `POST /items?title=…&kind=…&hours=…` | Raw binary ciphertext, content length or chunked transfer | `201`, committed item JSON |
| `GET /items/{id}` | Lowercase 32-hex ID | `200`, `application/octet-stream`, exact `Content-Length` |

Item fields are `id`, `title`, `kind`, `size`, `created`, `expires`, and `manager`.
Times are Unix seconds; `expires=0` means no expiry.
`retentionAdjusted=true` appears only in an upload response when retention was clamped; it is not persistent metadata.
Titles are trimmed, nonempty, at most 512 UTF-8 bytes, and contain no control characters.
Kinds are `files` and `configuration`; configuration publication requires manager authority.
Hours must be a nonnegative signed 64-bit integer.
Ordinary zero/unlimited or above-72-hour requests are clamped to 72 hours before duration arithmetic.
Managers may request zero or longer retention within the existing signed-nanosecond duration bound.

## Failure and storage semantics

Errors have fixed public text bodies: invalid input or incomplete upload `400`, denied source or publication `403`, absent/expired item or unsupported route/method `404`, concurrent upload `409`, upload deadline `408`, storage failure `503`, and quota/catalog exhaustion `507`.
Responses include `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
Uploads stream into private temporary storage, synchronize data and metadata, then publish by atomic directory rename.
Only one upload reserves quota at a time; reads continue independently.
The aggregate ciphertext quota and 512-item catalog limit are server-enforced.
Abandoned uploads are cleaned on startup; expired items are removed on inventory access and periodic sweeping.
Queue data and manager authority survive service restart and client disconnect.
Downloads do not consume or delete items.
An interrupted response can leave a committed upload; clients must read back the catalog before retrying, because POST is not idempotent.
The server stores opaque bytes and public metadata; it cannot validate encryption, passwords, archives or application-specific configuration contents.
