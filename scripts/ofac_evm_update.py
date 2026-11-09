#!/usr/bin/env python3
"""Download the OFAC SDN advanced XML and write EVM addresses to ofac_evm.txt.

Stdlib only. Core never calls this. A bad download keeps the previous file.
The official file is SDN_ADVANCED.XML on sanctionslistservice.ofac.treas.gov.
The legacy treasury.gov URL redirects there. Start URLs stay on treas.gov.
PublicationPreview answers 302 to a presigned URL on OFAC's own bucket
(OFAC_PUBLISH_BUCKET). That host is allowed only as a redirect target
reached from a treas.gov URL, never as a start URL.

Refuse to replace the list when the XML is under 1 MiB or the extract has
fewer than 100 EVM addresses, so an error page is never stored as an empty list.
"""

from __future__ import annotations

import io
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
# OFAC's PublicationPreview export 302s here. Presigned, so the path changes.
# Allowed only after a treas.gov URL, never as the URL this script requests first.
OFAC_PUBLISH_BUCKET = "wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com"
MIN_XML_BYTES = 1_000_000
MIN_ADDRESSES = 100
_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")
_FEATURE = "Digital Currency Address"
_REDIRECTS = {301, 302, 303, 307, 308}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _is_treas(url: str) -> bool:
    host = _hostname(url)
    return host == "treas.gov" or host.endswith(".treas.gov")


def _is_publish_bucket(url: str) -> bool:
    return _hostname(url) == OFAC_PUBLISH_BUCKET


def _host_allowed(url: str, *, from_treas: bool) -> bool:
    if _is_treas(url):
        return True
    return from_treas and _is_publish_bucket(url)


def _fetch(url: str) -> tuple[bytes, str]:
    opener = build_opener(_NoRedirect)
    current = url
    from_treas = False
    first = True
    for _ in range(4):
        if first:
            if not _is_treas(current):
                raise RuntimeError(f"host refused: {current}")
            first = False
        elif not _host_allowed(current, from_treas=from_treas):
            raise RuntimeError(f"host refused: {current}")
        request = Request(current, headers={"User-Agent": "satsgate-ofac-update"})
        try:
            with opener.open(request, timeout=60) as response:
                status = getattr(response, "status", 200)
                ctype = response.headers.get("Content-Type", "")
                final = response.geturl()
                if _is_treas(current):
                    final_ok = _is_treas(final)
                elif from_treas and _is_publish_bucket(current):
                    final_ok = _is_publish_bucket(final)
                else:
                    final_ok = False
                if not final_ok:
                    raise RuntimeError(f"host refused: {final}")
                if status != 200:
                    raise RuntimeError(f"HTTP {status}")
                if "xml" not in ctype.lower():
                    raise RuntimeError(f"unexpected content type {ctype!r}")
                return response.read(), final
        except HTTPError as exc:
            if exc.code in _REDIRECTS:
                loc = exc.headers.get("Location")
                if not loc:
                    raise RuntimeError("redirect without location") from exc
                from_treas = _is_treas(current)
                current = loc
                continue
            raise RuntimeError(f"HTTP {exc.code}") from exc
    raise RuntimeError("too many redirects")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _iter_end(xml_bytes: bytes):
    context = ET.iterparse(io.BytesIO(xml_bytes), events=("start", "end"))
    try:
        _event, root = next(context)
    except StopIteration as exc:
        raise ET.ParseError("empty document") from exc
    return context, root


def _feature_type_names(xml_bytes: bytes) -> dict[str, str]:
    """Reference table: FeatureType ID attribute → name. Namespace-agnostic."""
    names: dict[str, str] = {}
    context, root = _iter_end(xml_bytes)
    for event, elem in context:
        if event != "end" or _local(elem.tag) != "FeatureType":
            continue
        type_id = (elem.attrib.get("ID") or "").strip()
        text = (elem.text or "").strip()
        if type_id and text:
            names[type_id] = text
        elem.clear()
        root.clear()
    return names


def _legacy_feature_type(elem: ET.Element) -> str:
    """Old SDN shape: a FeatureType child element, not the ID reference table."""
    for child in elem:
        if _local(child.tag) != "FeatureType":
            continue
        text = (child.text or "").strip()
        if text:
            return text
    return ""


def _feature_addresses(elem: ET.Element, names: dict[str, str]) -> list[str]:
    type_id = (elem.attrib.get("FeatureTypeID") or "").strip()
    if type_id:
        type_name = names.get(type_id, "")
    else:
        type_name = _legacy_feature_type(elem)
    if not type_name.startswith(_FEATURE):
        return []
    found: list[str] = []
    for child in elem.iter():
        text = (child.text or "").strip()
        if _EVM.fullmatch(text):
            found.append(text.lower())
    return found


def extract_evm(xml_bytes: bytes) -> list[str]:
    """EVM addresses on features typed 'Digital Currency Address - …'.

    The live file names the type with a FeatureTypeID attribute looked up in
    the FeatureType reference table. A nested FeatureType text child is the
    older shape and is used only when the attribute is absent. Two streaming
    passes keep the ~128 MiB file from staying as a full tree.
    """
    try:
        names = _feature_type_names(xml_bytes)
        found: set[str] = set()
        context, root = _iter_end(xml_bytes)
        for event, elem in context:
            if event != "end" or _local(elem.tag) != "Feature":
                continue
            found.update(_feature_addresses(elem, names))
            elem.clear()
            root.clear()
    except ET.ParseError as exc:
        raise RuntimeError("parse error: SDN XML did not parse") from exc
    return sorted(found)


def write_list(path: Path, addresses: list[str], *, source: str) -> None:
    if len(addresses) < MIN_ADDRESSES:
        raise RuntimeError(f"too few addresses: {len(addresses)}; floor is {MIN_ADDRESSES}")
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
            raise RuntimeError(f"too small: XML is {len(body)} bytes, under {MIN_XML_BYTES}")
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
