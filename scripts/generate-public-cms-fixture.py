"""Regenerate a synthetic test-only CMS; fixed PUBLIC d=1, k=2, never real keys.
Requires the local PHP module built with cargo build -p gost-sign-php.
Independent Python integer arithmetic signs; the PHP/Rust CMS builder encodes.
Curve constants: RFC7836 A.2; formulas: RFC7091 section6.
The synthetic certificate is intentionally unsigned and conveys no trust.
"""
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
suffix = 'dylib' if sys.platform == 'darwin' else 'so'
extension = root / f'target/debug/libgost_sign_php.{suffix}'
php = '''$v=json_decode(stream_get_contents(STDIN),true,flags:JSON_THROW_ON_ERROR);
$c=hex2bin($v['content']); $cert=hex2bin($v['cert']);
$a=gost_sign_cades_signed_attributes($c,$cert);
echo json_encode(['digest'=>gost_sign_hash256($a),'cms'=>isset($v['signature'])?bin2hex(gost_sign_cades_assemble($c,$cert,hex2bin($v['signature']))):null]);'''
def call(values):
    return json.loads(subprocess.check_output(['php', '-n', '-d', f'extension={extension}', '-r', php], input=json.dumps(values).encode()))

p = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97', 16)
q = int('400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67', 16)
a = int('C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335', 16)
gx = int('91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28', 16)
gy = int('32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C', 16)
# The public key for d=1 is G. Extract only the literal synthetic certificate.
source = (root / 'crates/gost-sign-cms/src/lib.rs').read_text()
cert = bytes.fromhex(re.search(r'const SYNTHETIC_CERTIFICATE:.*?"([0-9a-f]+)"', source, re.S)[1])
needle = bytes.fromhex('0343000440') + bytes(64)
assert cert.count(needle) == 1
cert = cert.replace(needle, bytes.fromhex('0343000440') + gx.to_bytes(32,'little') + gy.to_bytes(32,'little'))
content = b'Public synthetic CMS fixture\x00\xff\r\n'
values = {'content': content.hex(), 'cert': cert.hex()}
digest = bytes.fromhex(call(values)['digest'])
e = int.from_bytes(digest, 'little') % q or 1
# k=2 means R=2G. Affine doubling independently computed with Python integers.
slope = ((3 * gx * gx + a) * pow(2 * gy, -1, p)) % p
r = ((slope * slope - 2 * gx) % p) % q
s = (r + 2 * e) % q  # s = r*d + k*e, PUBLIC d=1 and k=2
assert r and s
values['signature'] = (s.to_bytes(32,'big') + r.to_bytes(32,'big')).hex()
folder = root / 'crates/gost-sign-cms/tests/fixtures'
(folder / 'synthetic-certificate.der').write_bytes(cert)
(folder / 'synthetic-content.bin').write_bytes(content)
(folder / 'synthetic-cades.der').write_bytes(bytes.fromhex(call(values)['cms']))
print('Wrote synthetic public CMS test fixture (d=1, k=2).')
