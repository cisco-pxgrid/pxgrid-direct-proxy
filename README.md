# API Pagination Proxy

A deliberately small Rust HTTP proxy. It accepts inbound plaintext `GET` requests, preserves the path and query parameters, changes only the target server, adds outbound HTTP Basic Authentication from environment variables, and consolidates paginated JSON arrays into one streamed JSON document.

## Configuration

Copy the examples:

```sh
cp config.yaml.example config.yaml
cp .env.example .env
```

Set the real target URL and credentials. The inbound URL path is appended to `target.base_url`; query parameters are forwarded. In offset and page modes, the configured pagination parameters override inbound values.

`response.array_path` is an RFC 6901 JSON Pointer. For ServiceNow's `{ "result": [...] }`, use `/result`. The first successful response supplies the response shape; its configured array is streamed and replaced with the concatenated items from later pages.

Pagination modes:

- `offset`: increments the configured offset by `page_size`; stops when fewer than `page_size` items arrive.
- `page`: increments the configured page number; stops when fewer than `page_size` items arrive.
- `next_link`: follows the string at `next_link_path`; stops when it is absent or null. Absolute next links are supported.

`error_policy: terminate` reports a stream error after a later-page failure. `error_policy: complete` closes the JSON document with the data already received. HTTP headers are forwarded except `Host`, `Accept-Encoding`, and headers that look authentication-related (`Authorization`, proxy authorization, auth/token/credential names). The proxy always sends its own Basic Auth header and handles upstream compression itself.

Missing or invalid credential environment variables are logged by name (never by value) and returned as request errors. Upstream `401 Unauthorized` and `403 Forbidden` responses are logged as authentication failures and always terminate the response; they are never converted into a successful partial response by `error_policy: complete`.

If authentication fails before the first page produces data, the proxy returns a real HTTP `401` or `403` response. If it fails on a later page, the HTTP headers have already been sent, so the client receives a stream error and an incomplete response instead.

## Run locally

```sh
cp config.yaml.example config.yaml
cp .env.example .env
set -a; . ./.env; set +a
cargo run --release
curl 'http://localhost:3030/api/now/table/cmdb_ci_computer?sysparm_fields=sys_id&sysparm_limit=100000000'
```

## Docker

```sh
cp config.yaml.example config.yaml
cp .env.example .env
docker compose up --build
```

The runtime image is `scratch`. It contains the standard public CA bundle but no shell, package manager, or debugging tools. For a private CA, mount a PEM bundle and set `target.ca_bundle_path` to the mounted path.

## Logging

The proxy logs startup, inbound requests, header filtering counts, pagination mode, upstream page dispatch and status, page item counts, completion, and error-policy decisions. For operational troubleshooting, the username and password read from environment variables are logged as their first three characters followed by exactly six asterisks. On an upstream response error, it logs the complete inbound request details, complete upstream response headers, and the complete upstream payload wrapped at 60 characters per line. This can expose authorization headers, query values, and returned records; do not send these logs to a shared or untrusted destination. Set `RUST_LOG` to control verbosity; `debug` adds per-page diagnostics.

The Compose example configures Docker's `json-file` driver with three rotating 10 MB files (`max-size: 10m`, `max-file: 3`).

## Scope and limitations

The initial service supports GET only, one configured target, JSON responses, and one array to aggregate. It buffers each upstream page so it can validate and extract JSON, but does not buffer the complete result; items are sent to the caller as pages finish. The proxy must know the array location because generic JSON documents do not provide an unambiguous merge operation.
