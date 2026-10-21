#!/usr/bin/env bash
# Source this from your shell profile to make Node.js use the system CA store
# (OpenSSL's default file/dir) instead of its bundled roots.
# Appends --use-openssl-ca to NODE_OPTIONS once; never overwrites other options.
case " ${NODE_OPTIONS:-} " in
  *" --use-openssl-ca "*) ;;
  *) NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--use-openssl-ca"; export NODE_OPTIONS ;;
esac
