#!/usr/bin/env bash
# Lädt ClamAV für Windows (offizielles Paket von Cisco Talos auf GitHub), prüft die Signatur mit
# dem fest eingetragenen Schlüssel von Talos und legt die für Vigil nötigen Dateien nach
# target/clamav-win/ (wird vom Windows-Installer als Ordner "clamav" mitgeliefert).
# Mitgeliefert werden nur clamd, clamscan, freshclam, die Bibliotheken samt Laufzeit von
# Microsoft, die Zertifikate für die Virendaten und die Lizenztexte (GPL-2.0 und Beigaben).
# Aufruf: packaging/windows/fetch-clamav.sh
set -euo pipefail

VERSION="1.5.4"
# Fingerabdruck des Signaturschlüssels von Talos (research@sourcefire.com), gültig bis 2027-03-13
TALOS_FPR="5BADCA2665EF59DCF8A23D8B707F0DB480836771"
BASE="https://github.com/Cisco-Talos/clamav/releases/download/clamav-${VERSION}"
ZIP="clamav-${VERSION}.win.x64.zip"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DL="$ROOT/target/clamav-win-download"
OUT="$ROOT/target/clamav-win"

fehler() { echo "FEHLER: $*" >&2; exit 1; }
for t in python3 gpg unzip; do command -v "$t" >/dev/null || fehler "$t fehlt"; done

mkdir -p "$DL"
holen() {
  [ -s "$DL/$1" ] && return 0
  python3 -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$2" "$DL/$1.part"
  mv "$DL/$1.part" "$DL/$1"
}
holen "$ZIP" "$BASE/$ZIP"
holen "$ZIP.sig" "$BASE/$ZIP.sig"
holen talos.asc "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${TALOS_FPR}"

# Signatur prüfen: genau eine gültige Signatur des festen Schlüssels
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
gpg -q --import "$DL/talos.asc" 2>/dev/null || fehler "Schlüssel von Talos nicht lesbar"
STATUS="$(LANG=C gpg --status-fd 1 --verify "$DL/$ZIP.sig" "$DL/$ZIP" 2>/dev/null || true)"
echo "$STATUS" | grep -q "^\[GNUPG:\] VALIDSIG ${TALOS_FPR} " || fehler "Signatur von $ZIP ist ungültig"
echo "$STATUS" | grep -qE "BADSIG|ERRSIG" && fehler "Signatur von $ZIP ist ungültig"
echo "Signatur von $ZIP gültig (Talos ${TALOS_FPR})."

# Nur die nötigen Dateien auspacken
rm -rf "$OUT" "$DL/x"
mkdir -p "$OUT" "$DL/x"
unzip -q "$DL/$ZIP" -d "$DL/x"
SRC="$DL/x/clamav-${VERSION}.win.x64"
cp "$SRC"/clamd.exe "$SRC"/clamscan.exe "$SRC"/freshclam.exe "$OUT/"
cp "$SRC"/*.dll "$OUT/"
cp -r "$SRC/certs" "$OUT/certs"
mkdir -p "$OUT/COPYING"
cp "$SRC/COPYING.txt" "$OUT/COPYING/COPYING.txt"
cp "$SRC"/COPYING/* "$OUT/COPYING/"
cp "$SRC/README.md" "$OUT/README.md"
rm -rf "$DL/x"
echo "ClamAV $VERSION für Windows liegt in $OUT ($(du -sh "$OUT" | cut -f1))."
