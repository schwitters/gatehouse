#!/bin/bash
# scripts/build-deb.sh — Baut ein installierbares .deb-Paket für gatehouse.
#
# Verwendung:
#   ./scripts/build-deb.sh
#
# Ergebnis: gatehouse_<VERSION>_<ARCH>.deb im Projektverzeichnis

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="$(grep -m1 'project(gatehouse VERSION' "$PROJECT_ROOT/CMakeLists.txt" \
    | sed 's/.*VERSION \([0-9.]*\).*/\1/')"
ARCH="$(dpkg --print-architecture)"
PACKAGE_NAME="gatehouse"
DEB_FILENAME="${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
BUILD_DIR="${PROJECT_ROOT}/build-deb"
STAGING_DIR="${PROJECT_ROOT}/.deb-staging"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  gatehouse .deb Builder — v${VERSION} (${ARCH})"
echo "╚══════════════════════════════════════════════════════╝"
echo "  Ausgabe: ${PROJECT_ROOT}/${DEB_FILENAME}"
echo ""

# ── 1. Build-Abhängigkeiten ──────────────────────────────────────────────────
echo "[1/6] Build-Abhängigkeiten installieren..."
if ! command -v dpkg-deb &>/dev/null; then
    echo "FEHLER: dpkg-deb nicht gefunden – nur auf Debian/Ubuntu ausführbar." >&2
    exit 1
fi
sudo apt-get update -qq
sudo apt-get install -y -qq \
    cmake build-essential pkg-config \
    libsqlite3-dev libkrb5-dev libldap2-dev \
    libssl-dev libcurl4-openssl-dev libboost-all-dev \
    dpkg-dev

# ── 2. Kompilieren ───────────────────────────────────────────────────────────
echo "[2/6] Projekt kompilieren..."
rm -rf "${BUILD_DIR}"
cmake "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "${BUILD_DIR}" -- -j"$(nproc)"

# ── 3. Staging befüllen ──────────────────────────────────────────────────────
echo "[3/6] Dateien in Staging-Verzeichnis kopieren..."
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"

DESTDIR="${STAGING_DIR}" cmake --install "${BUILD_DIR}" --prefix /usr

# Konfigurationsverzeichnis
install -d -m 755 "${STAGING_DIR}/etc/gatehouse"
install -m 640 "${PROJECT_ROOT}/data/gatehouse.env.example" \
    "${STAGING_DIR}/etc/gatehouse/gatehouse.env.example"
# conffile: gatehouse.env muss physisch im Paket vorhanden sein.
# postinst überschreibt es NICHT, wenn der Admin es schon angepasst hat —
# dpkg merkt Änderungen und fragt beim Upgrade nach.
install -m 640 "${PROJECT_ROOT}/data/gatehouse.env.example" \
    "${STAGING_DIR}/etc/gatehouse/gatehouse.env"
install -m 644 "${PROJECT_ROOT}/config/guac_connection_template.json" \
    "${STAGING_DIR}/etc/gatehouse/guac_connection_template.json"

# Laufzeit-Zustandsverzeichnis (per postinst angelegt)
install -d -m 750 "${STAGING_DIR}/var/lib/gatehouse"

# Dev-Artefakte aus Staging entfernen (Crow-Header, cmake-Config, …)
rm -rf "${STAGING_DIR}/usr/include"
rm -rf "${STAGING_DIR}/usr/lib/cmake"
rm -rf "${STAGING_DIR}/usr/lib/pkgconfig"

# ── 4. DEBIAN-Metadaten ──────────────────────────────────────────────────────
echo "[4/6] DEBIAN-Metadaten erzeugen..."
DEBIAN_DIR="${STAGING_DIR}/DEBIAN"
mkdir -p "${DEBIAN_DIR}"

# Laufzeit-Abhängigkeiten ermitteln
LDAP_PKG="$(dpkg -l 'libldap2*' 2>/dev/null \
    | awk '/^ii/{print $2}' | grep -v '\-dev' | sort -r | head -1 || true)"
LDAP_PKG="${LDAP_PKG:-libldap-2.5-0}"

BOOST_PKG="$(dpkg -l 'libboost-system*' 2>/dev/null \
    | awk '/^ii/{print $2}' | grep -v '\-dev' | sort -r | head -1 || true)"
BOOST_PKG="${BOOST_PKG:-libboost-system1.83.0}"
#libboost-date-time1.83.0

BOOST_DATETIME_PKG="$(dpkg -l 'libboost-date-time*' 2>/dev/null \
    | awk '/^ii/{print $2}' | grep -v '\-dev' | sort -r | head -1 || true)"

BOOST_DATETIME_PKG="${BOOST_DATETIME_PKG:-libboost-date-time1.83.0}"

CURL_PKG="$(dpkg -l 'libcurl4*' 2>/dev/null \
    | awk '/^ii/{print $2}' | grep -v '\-dev' | sort -r | head -1 || true)"
CURL_PKG="${CURL_PKG:-libcurl4}"

DEPENDS="libsqlite3-0, libkrb5-3, libgssapi-krb5-2, libkadm5clnt-mit12 | libkadm5clnt-mit11"
DEPENDS="${DEPENDS}, ${LDAP_PKG}, libssl3t64, ${CURL_PKG}, ${BOOST_PKG},${BOOST_DATETIME_PKG}"

cat > "${DEBIAN_DIR}/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Lab Infrastructure <infra@company.de>
Depends: ${DEPENDS}
Section: admin
Priority: optional
Description: Gatehouse Authentication and Session Gateway
 C++20 HTTP gateway for authentication (Kerberos 5 or demo mode),
 session management, Kerberos ticket storage, invitation flow with
 email OTP, and Guacamole SSO integration.
EOF

cat > "${DEBIAN_DIR}/conffiles" << 'EOF'
/etc/gatehouse/gatehouse.env
EOF

# ── postinst ─────────────────────────────────────────────────────────────────
cat > "${DEBIAN_DIR}/postinst" << 'POSTINST'
#!/bin/bash
set -e

install -d -m 750 -o root -g root /var/lib/gatehouse

# /etc/gatehouse/gatehouse.env wird vom Paket als conffile ausgeliefert.
# Beim Erstinstall enthält es den Platzhalter aus der Example-Datei.
# Der Admin muss GATEHOUSE_MASTER_KEY_HEX setzen, bevor der Dienst startet.
if grep -q 'CHANGE_ME' /etc/gatehouse/gatehouse.env 2>/dev/null; then
    echo "  HINWEIS: /etc/gatehouse/gatehouse.env enthält noch Platzhalter."
    echo "  Bitte GATEHOUSE_MASTER_KEY_HEX eintragen, dann starten:"
    echo "    systemctl enable --now gatehouse"
fi

systemctl daemon-reload

if [ "$1" = "configure" ]; then
    systemctl enable gatehouse.service || true
fi

exit 0
POSTINST
chmod 755 "${DEBIAN_DIR}/postinst"

# ── prerm ─────────────────────────────────────────────────────────────────────
cat > "${DEBIAN_DIR}/prerm" << 'PRERM'
#!/bin/bash
set -e
if [ "$1" = "remove" ] || [ "$1" = "upgrade" ]; then
    systemctl stop    gatehouse.service 2>/dev/null || true
    systemctl disable gatehouse.service 2>/dev/null || true
fi
exit 0
PRERM
chmod 755 "${DEBIAN_DIR}/prerm"

# ── postrm ────────────────────────────────────────────────────────────────────
cat > "${DEBIAN_DIR}/postrm" << 'POSTRM'
#!/bin/bash
set -e
case "$1" in
    purge)
        rm -rf /etc/gatehouse
        rm -rf /var/lib/gatehouse
        ;;
esac
systemctl daemon-reload 2>/dev/null || true
exit 0
POSTRM
chmod 755 "${DEBIAN_DIR}/postrm"

# ── 5. Größe berechnen und control ergänzen ───────────────────────────────────
INSTALLED_SIZE_KB="$(du -sk "${STAGING_DIR}" | cut -f1)"
echo "Installed-Size: ${INSTALLED_SIZE_KB}" >> "${DEBIAN_DIR}/control"

# ── 6. .deb bauen ────────────────────────────────────────────────────────────
echo "[6/6] .deb-Paket bauen..."
cd "${PROJECT_ROOT}"
dpkg-deb --root-owner-group --build "${STAGING_DIR}" "${DEB_FILENAME}"
rm -rf "${STAGING_DIR}" "${BUILD_DIR}"

# Git-Tag setzen
if git -C "${PROJECT_ROOT}" tag -l "v${VERSION}" | grep -q "^v${VERSION}$"; then
    echo "  HINWEIS: Git-Tag v${VERSION} existiert bereits — übersprungen."
else
    git -C "${PROJECT_ROOT}" tag "v${VERSION}"
    echo "  Git-Tag v${VERSION} gesetzt."
fi

echo ""
echo "✓ Fertig: ${PROJECT_ROOT}/${DEB_FILENAME}"
echo ""
echo "  Installieren:    sudo dpkg -i ${DEB_FILENAME}"
echo "  Oder:            sudo apt install ./${DEB_FILENAME}"
echo "  Inhalt prüfen:   dpkg-deb -c ${DEB_FILENAME}"
