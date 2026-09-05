# API Pagination Proxy

A small Rust HTTPS proxy for paginated JSON APIs. Each client supplies HTTP Basic Authentication to the proxy; the proxy validates it and uses the same credentials for every request to the configured upstream origin while consolidating paginated JSON arrays into one streamed document.

## Configuration

Copy and edit the example:

```sh
cp config.yaml.example config.yaml
```

Set `target.base_url`, then configure `listen.tls.server_names` with every DNS name and IP address that clients use to reach the proxy. The inbound path is appended to `target.base_url`; ordinary query parameters are forwarded. In offset and page modes, configured pagination parameters override inbound values.

On its first start, the proxy creates `ca.pem`, `server.pem`, and `server-key.pem` in `listen.tls.certificate_directory`. The CA and server certificate are reused on later starts. Distribute only `ca.pem` to clients; keep the directory private because it contains the server private key. If the generated TLS material is incomplete, the service fails safely rather than replacing it.

`response.array_path` is an RFC 6901 JSON Pointer. For ServiceNow responses shaped as `{ "result": [...] }`, use `/result`. The first successful response supplies the response shape; its configured array is replaced by the concatenated items from later pages.

Pagination modes:

- `offset`: increments the configured offset by `page_size`; stops when fewer than `page_size` items arrive.
- `page`: increments the configured page number by one; stops when fewer than `page_size` items arrive.
- `next_link`: follows the string at `next_link_path`; stops when it is absent or null. Relative and same-origin absolute links are supported. Cross-origin links are rejected so credentials cannot leave the configured upstream origin.

The proxy accepts `GET` only. Clients must send one valid `Authorization: Basic ...` header. Missing or malformed credentials return `401` with a Basic challenge. Inbound headers are forwarded except `Host`, `Accept-Encoding`, and sensitive authentication, token, and credential headers. The inbound Basic header is handled separately and is the only credential sent upstream.

## Run locally

```sh
cp config.yaml.example config.yaml
cargo run --release

# Trust the generated CA and send client credentials.
curl --cacert tls/ca.pem -u username:password \
  "https://localhost:3030/api/now/table/cmdb_ci_computer?sysparm_fields=sys_id&sysparm_limit=100000000"
```

## Docker

```sh
docker compose up --build
```

Compose persists generated TLS material in `./tls`. Add that directory to secure backups if clients depend on this proxy identity; deleting it creates a new CA and requires clients to trust the replacement `tls/ca.pem`.

The runtime image is `scratch`. It contains the standard public CA bundle for outbound HTTPS but no shell or package manager. For a private upstream CA, mount a PEM bundle and set `target.ca_bundle_path` to the mounted path.

## Logging

The service logs startup, inbound requests, header filtering counts, pagination mode, upstream page dispatch and status, page item counts, completion, and error-policy decisions. Authentication and token-like headers are redacted from diagnostic logs. Upstream error response headers and payloads can still contain sensitive application data, so keep logs in a trusted destination. Set `RUST_LOG` to control verbosity; `debug` adds per-page diagnostics.

## Scope and limitations

The service supports GET only, one configured target, JSON responses, and one array to aggregate. It buffers each upstream page so it can validate and extract JSON, but does not buffer the complete result; items are sent to the caller as pages finish. The proxy must know the array location because generic JSON documents do not provide an unambiguous merge operation.


## CrowdStrike Falcon

Set `crowdstrike.enabled: true` in `config.yaml` to enable `GET /crowdstrike`. The caller supplies the CrowdStrike OAuth client ID and secret through HTTP Basic Authentication; the proxy exchanges them for a request-scoped OAuth token and does not save either value.

```sh
curl --cacert tls/ca.pem -u CROWDSTRIKE_CLIENT_ID:CROWDSTRIKE_CLIENT_SECRET \
  https://localhost:3030/crowdstrike
```

The endpoint retrieves managed devices and each enabled optional enrichment, then returns the Python-compatible JSON object with streamed `endpoints` and `unmanaged` arrays. Optional APIs that respond with 400, 403, or 404 are marked unavailable and skipped. Other failures terminate the request. Configure a regional CrowdStrike cloud with `crowdstrike.base_url` and control optional calls through `crowdstrike.features`.
