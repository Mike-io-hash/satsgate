#!/bin/sh
# Download DB-IP Country Lite for this month and replace the local database.
# CC BY 4.0. https://db-ip.com
# If this month's file is missing or does not open, keep the file already there.
# Never delete or truncate the current database.

set -eu

dest="${SATSGATE_GEOIP_DB:-/data/geoip/dbip-country-lite.mmdb}"
month=$(date -u +%Y-%m)
url="https://download.db-ip.com/free/dbip-country-lite-${month}.mmdb.gz"
tmp="${dest}.download"
mkdir -p "$(dirname "$dest")"

if ! curl -fsSL --retry 2 --max-time 120 -o "${tmp}.gz" "$url"; then
  echo "geoip update failed: could not download ${url}" >&2
  echo "kept the existing file" >&2
  rm -f "${tmp}.gz"
  exit 1
fi

if ! gzip -dc "${tmp}.gz" > "$tmp"; then
  echo "geoip update failed: gzip could not unpack the download" >&2
  echo "kept the existing file" >&2
  rm -f "${tmp}.gz" "$tmp"
  exit 1
fi
rm -f "${tmp}.gz"

if ! python3 - "$tmp" <<'PY'
import sys
try:
    import maxminddb
except ImportError:
    sys.stderr.write("geoip update failed: maxminddb is not installed\n")
    raise SystemExit(1)
path = sys.argv[1]
try:
    reader = maxminddb.open_database(path)
    reader.get("8.8.8.8")
    reader.close()
except Exception as exc:
    sys.stderr.write(f"geoip update failed: database did not open ({exc})\n")
    raise SystemExit(1)
PY
then
  echo "kept the existing file" >&2
  rm -f "$tmp"
  exit 1
fi

mv -f "$tmp" "$dest"
echo "wrote $dest from $url"
