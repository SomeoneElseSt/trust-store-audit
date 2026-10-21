#!/usr/bin/env bash
# Regenerate the self-signed fixture certificates (offline). Not needed to run tests.
set -euo pipefail
cd "$(dirname "$0")/fixtures"
for n in good1 good2 bad1 bad2; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null \
    -subj "/CN=trust-store-audit test $n" -days 36500 -out "$n.pem" 2>/dev/null
done
{ echo "# good1"; cat good1.pem; echo "# bad1"; cat bad1.pem; cat good2.pem; echo "# bad2 label"; echo "bad2 second label"; cat bad2.pem; } > bundle.pem
cat good1.pem good2.pem > clean.pem
for n in bad1 bad2; do
  printf '%s  %s\n' "$(openssl x509 -in "$n.pem" -noout -fingerprint -sha256 | cut -d= -f2)" "$n"
done > distrusted.txt
