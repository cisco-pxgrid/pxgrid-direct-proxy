# API Pagination Proxy Specification

## Purpose

Expose one local plaintext HTTP endpoint that translates each inbound GET into requests against one configured upstream target. The inbound path and ordinary query parameters are retained; the upstream origin is replaced and Basic Authentication is generated from environment variables.

## Configuration

Configuration is YAML and contains `listen.address`, `target.base_url`, `target.username_env`, `target.password_env`, optional `target.timeout_seconds`, optional `target.ca_bundle_path`, one `pagination` mode, and `response.array_path` plus `response.error_policy`.

The username and password values must never be stored in YAML. They are read from the named environment variables for each request. The Basic Auth header is created by the proxy and inbound authentication headers are not forwarded.

## Request translation

Only GET is accepted. Other methods receive HTTP 405. The upstream URL consists of `target.base_url`, the inbound request path, and the inbound query string. Query keys used by offset/page pagination are replaced with configured values. Next-link mode follows the link returned by the upstream response.

All inbound headers are forwarded except `Host`, `Accept-Encoding`, `Authorization`, `Proxy-Authorization`, and names containing `auth`, `token`, or `credential` case-insensitively. The proxy controls upstream content negotiation so it can transparently decompress responses before parsing JSON; it also controls the upstream Host and Basic Auth.

## Pagination

Offset mode sends `offset_parameter=start_offset` and `page_size_parameter=page_size`, then adds `page_size` to the offset after each full page. Page mode sends the configured starting page and size, then increments the page after each full page. Both stop when the array contains fewer items than the configured page size, including zero.

Next-link mode reads a string from `next_link_path` using JSON Pointer. Missing or null means completion; a non-string value is an error.

## Response streaming

The first successful upstream JSON document establishes the response shape. The configured `array_path` must identify an array. The proxy emits the document prefix, an opening array bracket, and items from each page in order. It emits commas between items and emits the preserved document suffix only after pagination ends. Therefore the caller receives one valid JSON document, while later pages are not held in memory as part of the complete result.

The proxy waits for a page response before emitting that page's items and may request the next page only after its termination information is known. Ordering is strict.

## Errors

Before the first valid page, failures terminate the request with a stream error. After output begins, `terminate` propagates an error and may leave the JSON document incomplete. `complete` emits the preserved suffix and closes the JSON document with the items already delivered. This policy is explicitly lossy and should be used only when partial data is acceptable.

Missing or invalid username/password environment variables are logged by variable name and returned as errors. Upstream HTTP 401 and 403 responses are classified as authentication failures, logged without credentials or response bodies, and always propagate as errors regardless of `error_policy`.

When either failure occurs before the first response chunk, the proxy returns the corresponding HTTP status (`401`/`403` for upstream authentication failures, `500` for missing or invalid credential variables). A later-page authentication failure propagates as a stream error because the response status and earlier bytes have already been sent.

## Security and deployment

The listener is plaintext HTTP and must be kept on a trusted network or behind a TLS-terminating reverse proxy. The container is built in a Rust builder stage and runs from `scratch`. The standard CA bundle is copied into the image; a private PEM CA bundle can be mounted read-only and selected with `target.ca_bundle_path`.

## Logging

The service emits structured tracing logs for startup, request acceptance/rejection, header filtering counts, pagination mode, each upstream page dispatch and status, page sizes, response completion, and error-policy decisions. For operational troubleshooting, it logs the username and password read from environment variables as their first three characters followed by exactly six asterisks. When an upstream response causes an error, the log must include the complete inbound request details, complete upstream response headers, and complete upstream payload with lines wrapped at 60 characters. This may expose authorization headers, query values, and returned records, so error logs must be treated as sensitive. Docker Compose configures the `json-file` driver with `max-size: 10m` and `max-file: 3`.
