# API Pagination Proxy Specification

## Purpose

Expose one HTTPS endpoint that translates each inbound GET into requests against one configured upstream target. The inbound path and ordinary query parameters are retained, the upstream origin is substituted, and the client supplied HTTP Basic credentials are used for the upstream requests.

## Configuration

Configuration is YAML and contains `listen.address`, `listen.tls.certificate_directory`, `listen.tls.server_names`, `target.base_url`, optional `target.timeout_seconds`, optional `target.ca_bundle_path`, one `pagination` mode, and `response.array_path` plus `response.error_policy`.

On first startup, the service generates a private local CA plus a server certificate with SAN entries from `listen.tls.server_names`. It writes `ca.pem`, `server.pem`, and `server-key.pem` to `listen.tls.certificate_directory`. If all files exist, they are reused. If only some exist, startup fails. The CA private key is discarded after generating the server certificate; the server private key remains private in the persisted certificate directory.

## Request translation

Only GET is accepted. Other methods receive HTTP 405. The client must supply valid HTTP Basic Authentication. A missing or invalid header returns HTTP 401 and a `WWW-Authenticate: Basic` challenge.

The upstream URL consists of `target.base_url`, the inbound request path, and the inbound query string. Query keys used by offset and page pagination are replaced with configured values. Next-link mode follows a relative or same-origin absolute link returned by the upstream response. Cross-origin next links are rejected before credentials are sent.

All inbound headers are forwarded except `Host`, `Accept-Encoding`, and names containing `auth`, `token`, or `credential` case-insensitively. The proxy controls upstream content negotiation and sends the validated inbound Basic header separately on every upstream request.

## Pagination

Offset mode sends `offset_parameter=start_offset` and `page_size_parameter=page_size`, then adds `page_size` to the offset after each full page. Page mode sends the configured starting page and size, then increments the page after each full page. Both stop when the array contains fewer items than the configured page size, including zero.

Next-link mode reads a string from `next_link_path` using JSON Pointer. Missing or null means completion; a non-string value or a link for another origin is an error.

## Response streaming

The first successful upstream JSON document establishes the response shape. The configured `array_path` must identify an array. The proxy emits the document prefix, an opening array bracket, and items from each page in order. It emits commas between items and emits the preserved document suffix only after pagination ends. Therefore the caller receives one valid JSON document while later pages are not held in memory as part of the complete result.

The proxy waits for a page response before emitting that page items and may request the next page only after its termination information is known. Ordering is strict.

## Errors

Before the first valid page, failures terminate the request with a real HTTP error. After output begins, `terminate` propagates a stream error and may leave the JSON document incomplete. `complete` emits the preserved suffix and closes the JSON document with the items already delivered. This policy is lossy and should be used only when partial data is acceptable.

Upstream HTTP 401 and 403 are classified as authentication failures and always terminate the response. If they happen before the first response chunk, the client receives the corresponding status. Later failures propagate as a stream error because response headers and earlier bytes have already been sent.

## Security and deployment

The listener is HTTPS only. Each client must trust the generated `ca.pem`; clients must use a hostname or IP address present in `listen.tls.server_names`. Docker Compose mounts the certificate directory read-write even though the rest of the container filesystem is read-only. The runtime image is built from `scratch`; the standard CA bundle is copied into the image for outbound public HTTPS, and a private PEM CA bundle can be mounted read-only and selected with `target.ca_bundle_path`.

## Logging

The service emits structured logs for startup, request acceptance or rejection, header filtering counts, pagination mode, each upstream page dispatch and status, page sizes, response completion, and error-policy decisions. Authentication, token, and credential-like headers are redacted from diagnostic logs. Upstream response payloads and non-sensitive headers may still contain sensitive data and must be treated accordingly.


## CrowdStrike endpoint

When the optional `crowdstrike` configuration block has `enabled: true`, `GET /crowdstrike` is available. It requires HTTP Basic Authentication whose username and password are used only as CrowdStrike OAuth client ID and client secret. The proxy derives all Falcon URLs from `crowdstrike.base_url`, uses the resulting OAuth token only for the active request, and retains no credentials locally.

The endpoint gathers hosts and configured enrichments, flattens managed and unmanaged assets into the response shape used by `crowdstrike-example/onpremservice.py`, and streams the `endpoints` and `unmanaged` arrays. Missing optional API scopes return 400, 403, or 404 and are skipped; other failures, including exhausted 429 retries, fail the request.
