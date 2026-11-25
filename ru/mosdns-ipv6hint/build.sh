#!/bin/sh
# Build the pinned client resolver with its single local response filter.
# Usage: sh build.sh /path/to/output-binary
set -eu
test "$#" -eq 1
target=$(realpath -m -- "$1")
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export CGO_ENABLED=0
export GOTOOLCHAIN=local GOWORK=off
export GOFLAGS=
export GOSUMDB=sum.golang.org
module=github.com/IrineSistiana/mosdns/v5
cd "$work"
go mod download -json "$module@v5.3.4" >module.json
src=$(python3 - <<'PY'
import json
from pathlib import Path
m = json.loads(Path("module.json").read_text())
if m.get("Sum") != "h1:Vj1TazzrdzCwJEF79GdFpAet6qMFC8a9JQOmHe9KlUM=":
    raise SystemExit("Unexpected upstream module checksum")
print(m["Dir"])
PY
)
cp -R -- "$src" source
chmod -R u+w source
cd source
package=plugin/executable/strip_ipv6hint
mkdir -- "$package"
cp -- "$here"/strip_ipv6hint*.go "$package/"
printf 'package main\nimport _ "%s/%s"\n' "$module" "$package" >awg_filter.go
go mod download
go mod verify
go test -p 2 -mod=readonly "./$package"
go build -p 2 -mod=readonly -trimpath -ldflags '-s -w -X main.version=v5.3.4+awg-ipv4dns.2' -o "$target" .
