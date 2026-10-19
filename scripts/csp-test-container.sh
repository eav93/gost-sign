#!/bin/sh
# TEST ONLY: executed inside a disposable container, never on the host.
set -eu
[ -f /.dockerenv ] && [ -f /test-gamma/kis_1 ] && [ -d /out ] || { echo "Disposable test container required" >&2; exit 2; }
umask 077
export PATH=/opt/cprocsp/bin/amd64:/opt/cprocsp/sbin/amd64:$PATH
mkdir -p /var/opt/cprocsp/dsrf/db1 /var/opt/cprocsp/dsrf/db2
cp /test-gamma/kis_1 /var/opt/cprocsp/dsrf/db1/kis_1
cp /test-gamma/kis_1 /var/opt/cprocsp/dsrf/db2/kis_1
cpconfig -hardware rndm -del BIO_TUI || true
container='\\.\HDIMAGE\gost-sign-public-interop'
test_password="${GOST_CSP_TEST_PASSWORD-123456}"
csptest -keyset -newkeyset -container "$container" -provtype 80 -keytype exchange -exportable -password "$test_password"
csptest -keyset -container "$container" -provtype 80 -password "$test_password" -makecert
certmgr -install -container "$container" -silent
printf '123456\n' | certmgr -export -pfx -container "$container" -dest /out/test-csp.pfx -pin "$test_password"
certmgr -export -container "$container" -dest /out/test-csp.cer -silent
cp -R /var/opt/cprocsp/keys/root /out/hdimage-test
