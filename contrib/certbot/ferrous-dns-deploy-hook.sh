#!/bin/sh
# certbot deploy hook for Ferrous DNS: installs a new or renewed certificate where
# the DoT/DoQ listeners read it, then restarts the server, which loads
# certificates only at startup.
# Guide: https://ferrous-networking.github.io/ferrous-dns/operations/tls-reverse-proxy/
#
#   certbot certonly ... --deploy-hook /usr/local/sbin/ferrous-dns-deploy-hook
#
# Not in renewal-hooks/deploy/: certbot runs those for every certificate, and the
# renewal of another one would overwrite these files. Given with --deploy-hook,
# certbot keeps it with this certificate's renewal settings only.
#
# certbot sets RENEWED_LINEAGE to /etc/letsencrypt/live/<name>. The four
# settings below match contrib/systemd/ferrous-dns.service; override them in the
# environment or edit them here. For Docker, point CERT and KEY at the files in the
# mounted /data directory, set OWNER=1000:1000 and RESTART="docker restart ferrous-dns".
set -eu

CERT=${FERROUS_DNS_CERT:-/var/lib/ferrous-dns/tls/dot-cert.pem}
KEY=${FERROUS_DNS_KEY:-/var/lib/ferrous-dns/tls/dot-key.pem}
OWNER=${FERROUS_DNS_OWNER:-ferrous-dns:ferrous-dns}
RESTART=${FERROUS_DNS_RESTART:-systemctl restart ferrous-dns}

install_private() {
    # Written next to the target and renamed over it, so the server never reads half a file.
    dir=$(dirname "$2")
    if [ ! -d "$dir" ]; then
        install -d -m 0700 "$dir"
        chown "$OWNER" "$dir"
    fi
    install -m 0600 "$1" "$2.new"
    chown "$OWNER" "$2.new"
    mv -f "$2.new" "$2"
}

install_private "$RENEWED_LINEAGE/fullchain.pem" "$CERT"
install_private "$RENEWED_LINEAGE/privkey.pem" "$KEY"
$RESTART
