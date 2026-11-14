# Changelog

## Unreleased

Work towards 2.0.0. Nothing in this section has been published.

### Added

- A test suite built on `node:test`, run with `npm test`. It covers the
  name database, the DNS server over UDP and TCP, the HTTP API, the
  command line program and the contents of the npm package.
- `close()` on `NameDB` and `ApiServer`. `NameServer.close()` returns a
  promise.
- An allowlist of published files in `package.json`.
- A lockfile and a CI workflow.

### Fixed

- A query over TCP that gets no answer no longer leaves the connection
  open until the idle timeout; the connection is closed.

## 1.1.1 (2025-05-12)

- Optional HTTP Basic authentication for the API (`--http-api-user`,
  `--http-api-password`).

## 1.1.0 (2025-05-10)

- A host can have several A, AAAA, TXT and MX records. The new `/record`
  API call adds, sets, removes and clears single values.

## 1.0.10 (2025-05-10)

- A host name may start with an underscore.

## 1.0.1 to 1.0.9 (2025-04-06 to 2025-04-07)

- MX records and simplified domain handling.
- `merge` parameter for `/host`.
- Synthesised NS and SOA records for served domains.
- Logging, and less frequent writes of the configuration file.
- Queries for names outside the served domains get no answer.
- `/stats` API call.
- Fixes to host and domain name validation.

## 1.0.0 (2025-04-06)

- Initial release.
