#!/usr/bin/env bash
#
# Packs the iPlus fork NuGet packages (iPlus.Microsoft.Data.SqlClient and siblings)
# into ../packages-local and purges stale versions from the redirected NuGet cache.
#
# Usage:
#   ./pack-iplus-packages.sh [version]
#
#   version   Package version to pack (default: 7.1.1-iplus.3)
#
# Notes:
# - Do NOT pass -p:Version= to the main SqlClient package: dependency ranges are
#   derived from SqlClientPackageVersion / SqlServerPackageVersion.
# - The machine's NuGet global-packages store is redirected to
#   /home/damir/SHARED/Devel/iPlusGit/V5/packages — stale fork versions are purged
#   there after packing, otherwise restore picks the old package.
# - NuGetAudit=false: upstream 7.1.1 pins System.Security.Cryptography.Pkcs 9.0.18,
#   which now has known advisories (GHSA-2fmv-rv2c-59x7, GHSA-846f-f764-76mx).
#   Restore treats those as errors otherwise.

set -euo pipefail

VERSION="${1:-7.1.1-iplus.3}"
SQLSERVER_VERSION="1.1.0-preview1-iplus.0"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$REPO_ROOT/../packages-local"
NUGET_CACHE="/home/damir/SHARED/Devel/iPlusGit/V5/packages"
SIGNING_KEY="$REPO_ROOT/tools/iplus-fork.snk"

cd "$REPO_ROOT"

echo "==> Packing iPlus fork packages, version $VERSION"
echo "    Output: $OUTPUT_DIR"

dotnet pack src/Microsoft.Data.SqlClient.Extensions/Abstractions/src/Abstractions.csproj \
  -c Release -p:Version="$VERSION" -p:SigningKeyPath="$SIGNING_KEY" -p:NuGetAudit=false -o "$OUTPUT_DIR"

dotnet pack src/Microsoft.Data.SqlClient.Internal/Logging/src/Logging.csproj \
  -c Release -p:Version="$VERSION" -p:SigningKeyPath="$SIGNING_KEY" -p:NuGetAudit=false -o "$OUTPUT_DIR"

dotnet pack src/Microsoft.SqlServer.Server/Microsoft.SqlServer.Server.csproj \
  -c Release -p:SqlServerPackageVersion="$SQLSERVER_VERSION" -p:SigningKeyPath="$SIGNING_KEY" -p:NuGetAudit=false -o "$OUTPUT_DIR"

dotnet pack src/Microsoft.Data.SqlClient/src/Microsoft.Data.SqlClient.csproj \
  -c Release -p:SqlClientPackageVersion="$VERSION" -p:SqlServerPackageVersion="$SQLSERVER_VERSION" \
  -p:SigningKeyPath="$SIGNING_KEY" -p:NuGetAudit=false -o "$OUTPUT_DIR"

echo "==> Purging stale fork versions from NuGet cache: $NUGET_CACHE"
rm -rf "$NUGET_CACHE"/iplus.microsoft.data.sqlclient* \
       "$NUGET_CACHE"/iplus.microsoft.sqlserver.server* 2>/dev/null || true

echo "==> Verifying packed packages"
MAIN_NUPKG="$OUTPUT_DIR/iPlus.Microsoft.Data.SqlClient.$VERSION.nupkg"
if [[ ! -f "$MAIN_NUPKG" ]]; then
  echo "ERROR: $MAIN_NUPKG was not created." >&2
  exit 1
fi

echo "-- lib contents:"
unzip -l "$MAIN_NUPKG" 'lib/*' | grep -E 'net10\.0[^/]*/Microsoft\.Data\.SqlClient\.dll' || {
  echo "ERROR: net10.0 libs missing from nupkg." >&2
  exit 1
}

echo "-- dependency groups:"
unzip -p "$MAIN_NUPKG" '*.nuspec' | grep -E '<(group|dependency) ' | sed 's/^ *//'

echo "==> Done. Packages in $OUTPUT_DIR:"
ls -1 "$OUTPUT_DIR" | grep "$VERSION"
