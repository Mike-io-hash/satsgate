#!/usr/bin/env python3
"""Download the OFAC SDN advanced XML and write EVM addresses to ofac_evm.txt.

Stdlib only. Core never calls this. A bad download keeps the previous file.
The official file is SDN_ADVANCED.XML on sanctionslistservice.ofac.treas.gov.
Start URLs stay on treas.gov. PublicationPreview answers 302 to a presigned
URL on OFAC's own bucket (OFAC_PUBLISH_BUCKET). That host is allowed only as
a redirect target reached from a treas.gov URL, never as a start URL. There
is no second source: if PRIMARY fails, the previous file stays and the
process exits non-zero.

The download is written to a temporary file in bounded chunks and parsed
twice from that file. The XML is not held in memory. Presigned query strings
are not printed or stored. The public source line is the canonical PRIMARY URL.

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
# OFAC's PublicationPreview export 302s here. Presigned, so the path changes.
# Allowed only after a treas.gov URL, never as the URL this script requests first.
OFAC_PUBLISH_BUCKET = "wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com"
MIN_XML_BYTES = 1_000_000
MIN_ADDRESSES = 100
_CHUNK_BYTES = 64 * 1024
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


def _host_only(url: str) -> str:
    return _hostname(url) or "unknown"


def _close_response(response) -> None:
    close = getattr(response, "close", None)
    if close is None:
        return
    try:
        close()
    except OSError:
        return


def _public_failure(exc: BaseException) -> str:
    """A reason safe to print. Never a URL, query, or presigned parameter."""
    if not isinstance(exc, RuntimeError):
        return "download failed"
    text = str(exc)
    lowered = text.lower()
    if "://" in text or "?" in text or "x-amz-" in lowered or "signature=" in lowered:
        return "download failed"
    return text


def _fetch(url: str) -> tuple[Path, int]:
    """Stream ``url`` to a new temporary file. The caller deletes the file.

    Returns the path and the number of bytes actually written. Content-Length
    is not used as that count. ``read`` is always bounded.
    """
    fd, name = tempfile.mkstemp(prefix=".ofac-download-")
    os.close(fd)
    dest = Path(name)
    try:
        size = _fetch_into(url, dest)
    except Exception:
        try:
            dest.unlink()
        except OSError:
            pass
        raise
    return dest, size


def _fetch_into(url: str, dest: Path) -> int:
    opener = build_opener(_NoRedirect)
    current = url
    from_treas = False
    first = True
    for _ in range(4):
        if first:
            if not _is_treas(current):
                raise RuntimeError(f"host refused: {_host_only(current)}")
            first = False
        elif not _host_allowed(current, from_treas=from_treas):
            raise RuntimeError(f"host refused: {_host_only(current)}")
        request = Request(current, headers={"User-Agent": "satsgate-ofac-update"})
        try:
            response = opener.open(request, timeout=60)
        except HTTPError as exc:
            code = exc.code
            location = exc.headers.get("Location") if exc.headers is not None else None
            _close_response(exc)
            if code in _REDIRECTS:
                if not location:
                    raise RuntimeError("redirect without location") from None
                from_treas = _is_treas(current)
                current = location
                continue
            raise RuntimeError(f"HTTP {code}") from None
        except (URLError, TimeoutError, OSError) as exc:
            raise RuntimeError("download failed") from exc
        try:
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
                raise RuntimeError(f"host refused: {_host_only(final)}")
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            if "xml" not in ctype.lower():
                raise RuntimeError(f"unexpected content type {ctype!r}")
            return _copy_chunks(response, dest)
        finally:
            _close_response(response)
    raise RuntimeError("too many redirects")


def _copy_chunks(response, dest: Path) -> int:
    total = 0
    with dest.open("wb") as handle:
        while True:
            block = response.read(_CHUNK_BYTES)
            if not block:
                break
            handle.write(block)
            total += len(block)
    return total


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _walk(path: Path, on_end) -> None:
    """Visit each element at its end, then free what no open parent still needs.

    Children of a ``Feature`` stay until that feature is handled, so the parent
    can still read their text. Every other finished element is cleared and
    unlinked. The live set is the open path plus the feature currently ending.
    """
    context = ET.iterparse(os.fspath(path), events=("start", "end"))  # nosec B314
    stack: list[ET.Element] = []
    for event, elem in context:
        if event == "start":
            stack.append(elem)
            continue
        on_end(elem)
        if stack and stack[-1] is elem:
            stack.pop()
        inside_feature = any(_local(ancestor.tag) == "Feature" for ancestor in stack)
        if inside_feature:
            continue
        elem.clear()
        if stack and len(stack[-1]) and stack[-1][-1] is elem:
            del stack[-1][-1]


def _feature_type_names(path: Path) -> dict[str, str]:
    """Reference table: FeatureType ID attribute → name. Namespace-agnostic."""
    names: dict[str, str] = {}

    def on_end(elem: ET.Element) -> None:
        if _local(elem.tag) != "FeatureType":
            return
        type_id = (elem.attrib.get("ID") or "").strip()
        text = (elem.text or "").strip()
        if type_id and text:
            names[type_id] = text

    _walk(path, on_end)
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


def extract_evm(path: Path) -> list[str]:
    """EVM addresses on features typed 'Digital Currency Address - …'.

    The live file names the type with a FeatureTypeID attribute looked up in
    the FeatureType reference table. A nested FeatureType text child is the
    older shape and is used only when the attribute is absent. Two passes over
    the same local file keep the type table available when it follows the
    features, without a second download and without holding the XML.
    """
    try:
        names = _feature_type_names(path)
        found: set[str] = set()

        def on_end(elem: ET.Element) -> None:
            if _local(elem.tag) != "Feature":
                return
            found.update(_feature_addresses(elem, names))

        _walk(path, on_end)
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
    downloaded: Path | None = None
    try:
        downloaded, size = _fetch(PRIMARY)
        if size < MIN_XML_BYTES:
            raise RuntimeError(f"too small: XML is {size} bytes, under {MIN_XML_BYTES}")
        addresses = extract_evm(downloaded)
        write_list(dest, addresses, source=PRIMARY)
    except Exception as exc:  # noqa: BLE001
        print(f"ofac update failed: {_public_failure(exc)}", file=sys.stderr)
        print("kept the existing file", file=sys.stderr)
        return 1
    finally:
        if downloaded is not None:
            try:
                downloaded.unlink()
            except OSError:
                pass
    print(f"wrote {dest} ({len(addresses)} addresses)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
