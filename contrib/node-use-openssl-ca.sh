#!/usr/bin/env bash
# Source this from your shell profile to make Node.js use the system CA store
# (OpenSSL's default file/dir) instead of its bundled roots.
# Appends --use-openssl-ca to NODE_OPTIONS once; never overwrites other options.
# Official nodejs.org builds find no OpenSSL store on macOS, so point them at a
# patched bundle unless SSL_CERT_FILE is already set.
if [ -z "${SSL_CERT_FILE:-}" ] && [ -f /etc/ssl/cert.pem ]; then
  export SSL_CERT_FILE=/etc/ssl/cert.pem
fi
case " ${NODE_OPTIONS:-} " in
  *" --use-openssl-ca "*) ;;
  *) NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--use-openssl-ca"; export NODE_OPTIONS ;;
esac
