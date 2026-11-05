#!/usr/bin/env python3
"""Download the OFAC SDN advanced XML and write EVM addresses to ofac_evm.txt.

Stdlib only. Core never calls this. A bad download keeps the previous file.
The official file is SDN_ADVANCED.XML on sanctionslistservice.ofac.treas.gov.
The legacy treasury.gov URL redirects there. Redirects are followed only to
treas.gov hosts.

Refuse to replace the list when the XML is under 1 MiB or the extract has
fewer than 100 EVM addresses, so an error page is never stored as an empty list.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

PRIMARY = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_ADVANCED.XML"
LEGACY = "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml"
MIN_XML_BYTES = 1_000_000
MIN_ADDRESSES = 100
_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")
_FEATURE = "Digital Currency Address"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _host_ok(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host == "treas.gov" or host.endswith(".treas.gov")


def _fetch(url: str) -> tuple[bytes, str]:
    opener = build_opener(_NoRedirect)
    current = url
    for _ in range(4):
        if not _host_ok(current):
            raise RuntimeError(f"refusing host {current}")
        request = Request(current, headers={"User-Agent": "satsgate-ofac-update"})
        try:
            with opener.open(request, timeout=60) as response:
                status = getattr(response, "status", 200)
                ctype = response.headers.get("Content-Type", "")
                final = response.geturl()
                if not _host_ok(final):
                    raise RuntimeError(f"refusing final host {final}")
                if status != 200:
                    raise RuntimeError(f"HTTP {status}")
                if "xml" not in ctype.lower():
                    raise RuntimeError(f"unexpected content type {ctype!r}")
                return response.read(), final
        except HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                loc = exc.headers.get("Location")
                if not loc:
                    raise RuntimeError("redirect without location") from exc
                current = loc
                continue
            raise RuntimeError(f"HTTP {exc.code}") from exc
    raise RuntimeError("too many redirects")


def extract_evm(xml_bytes: bytes) -> list[str]:
    """EVM addresses on features typed 'Digital Currency Address - …'."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise RuntimeError("SDN XML did not parse") from exc
    found: set[str] = set()
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "Feature":
            continue
        feature_type = ""
        values: list[str] = []
        for child in element.iter():
            name = child.tag.rsplit("}", 1)[-1]
            text = (child.text or "").strip()
            if name == "FeatureType" and text:
                feature_type = text
            if _EVM.fullmatch(text):
                values.append(text.lower())
        if feature_type.startswith(_FEATURE):
            found.update(values)
    return sorted(found)


def write_list(path: Path, addresses: list[str], *, source: str) -> None:
    if len(addresses) < MIN_ADDRESSES:
        raise RuntimeError(f"refusing to write {len(addresses)} addresses; floor is {MIN_ADDRESSES}")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    body = "\n".join(
        [f"# source={source} generated={stamp} count={len(addresses)}", *addresses, ""]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".ofac-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def main() -> int:
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SATSGATE_OFAC_EVM_FILE", "/data/ofac/ofac_evm.txt"))
    try:
        try:
            body, source = _fetch(PRIMARY)
        except (RuntimeError, URLError, TimeoutError) as exc:
            print(f"primary download failed: {exc}", file=sys.stderr)
            body, source = _fetch(LEGACY)
        if len(body) < MIN_XML_BYTES:
            raise RuntimeError(f"XML is {len(body)} bytes, under {MIN_XML_BYTES}")
        addresses = extract_evm(body)
        write_list(dest, addresses, source=source)
    except Exception as exc:  # noqa: BLE001
        print(f"ofac update failed: {exc}", file=sys.stderr)
        print("kept the existing file", file=sys.stderr)
        return 1
    print(f"wrote {dest} ({len(addresses)} addresses)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
