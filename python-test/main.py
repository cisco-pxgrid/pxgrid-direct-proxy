#!/usr/bin/env python3

import sys
import urllib.error
import urllib.request


def print_response(response) -> None:
    print(f"HTTP {response.status} {response.reason}")
    for name, value in response.headers.items():
        print(f"{name}: {value}")
    print()

    while chunk := response.read(64 * 1024):
        sys.stdout.buffer.write(chunk)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <url>", file=sys.stderr)
        return 2

    request = urllib.request.Request(
        sys.argv[1],
        headers={"Accept": "application/json"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            print_response(response)
    except urllib.error.HTTPError as error:
        with error:
            print_response(error)
    except urllib.error.URLError as error:
        print(f"GET failed: {error.reason}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
