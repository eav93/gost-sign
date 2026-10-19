//! CryptoPro-A / XchA parameters from RFC4357 section11.4; cofactor1.
//! TC26-256-B is the same curve per RFC9215 AppendixC.
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::{U256, const_monty_form, const_monty_params};

const P: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
const Q: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893");
const B: U256 =
    U256::from_be_hex("00000000000000000000000000000000000000000000000000000000000000A6");
const_monty_params!(
    FieldModulus,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"
);
const_monty_params!(
    ScalarModulus,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"
);
const_monty_form!(Field, FieldModulus);
const_monty_form!(Scalar, ScalarModulus);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Point {
    Infinity,
    Affine { x: Field, y: Field },
}

fn generator() -> Point {
    Point::Affine {
        x: Field::new(&U256::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )),
        y: Field::new(&U256::from_be_hex(
            "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
        )),
    }
}

// Affine group law, used only on public values (or published test scalars).
fn add(lhs: Point, rhs: Point) -> Point {
    let (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) = (lhs, rhs) else {
        return if lhs == Point::Infinity { rhs } else { lhs };
    };
    let (numerator, denominator) = if x1 == x2 {
        if y1 == -y2 {
            return Point::Infinity;
        }
        (
            Field::new(&U256::from(3u8)) * x1.square()
                + Field::new(&U256::from_be_hex(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
                )),
            y1.double(),
        )
    } else {
        (y2 - y1, x2 - x1)
    };
    // Nonzero denominator in a prime field: inverse exists. The equal/inverse
    // and y=0 cases have already returned infinity above.
    let inverse = Option::<Field>::from(denominator.invert()).expect("nonzero field denominator");
    let slope = numerator * inverse;
    let x = slope.square() - x1 - x2;
    Point::Affine {
        x,
        y: slope * (x1 - x) - y1,
    }
}

fn multiply(point: Point, scalar: U256) -> Point {
    let mut result = Point::Infinity;
    for byte in scalar.to_be_bytes().as_slice() {
        for bit in (0..8).rev() {
            result = add(result, result);
            if (byte >> bit) & 1 == 1 {
                result = add(result, point);
            }
        }
    }
    result
}

fn decode_public_key(x: &[u8; 32], y: &[u8; 32]) -> Option<Point> {
    let x = U256::from_be_slice(x);
    let y = U256::from_be_slice(y);
    // Reject noncanonical encodings rather than reducing coordinates mod p.
    if x >= P || y >= P {
        return None;
    }
    let x = Field::new(&x);
    let y = Field::new(&y);
    if y.square()
        != x.square() * x
            + Field::new(&U256::from_be_hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
            )) * x
            + Field::new(&B)
    {
        return None;
    }
    let point = Point::Affine { x, y };
    if multiply(point, Q) != Point::Infinity {
        return None;
    }
    Some(point)
}

fn digest_scalar(digest: &[u8; 32]) -> Scalar {
    let e = Scalar::new(&U256::from_be_slice(digest));
    if e == Scalar::ZERO { Scalar::ONE } else { e }
}

fn verify_integers(
    digest_be: &[u8; 32],
    public_x_be: &[u8; 32],
    public_y_be: &[u8; 32],
    r_be: &[u8; 32],
    s_be: &[u8; 32],
) -> bool {
    let r = U256::from_be_slice(r_be);
    let s = U256::from_be_slice(s_be);
    if r == U256::ZERO || s == U256::ZERO || r >= Q || s >= Q {
        return false;
    }
    let Some(public) = decode_public_key(public_x_be, public_y_be) else {
        return false;
    };
    let e = digest_scalar(digest_be);
    let inverse =
        Option::<Scalar>::from(e.invert()).expect("nonzero scalar in prime subgroup order");
    let z1 = (Scalar::new(&s) * inverse).retrieve();
    let z2 = (-Scalar::new(&r) * inverse).retrieve();
    match add(multiply(generator(), z1), multiply(public, z2)) {
        Point::Infinity => false,
        Point::Affine { x, .. } => Scalar::new(&x.retrieve()).retrieve() == r,
    }
}

/// Verify a GOST 34.10-2012 signature on the CryptoPro-A curve.
///
/// Curve aliases: CryptoPro-A (1.2.643.2.2.35.1), CryptoPro-XchA
/// (1.2.643.2.2.36.0), and TC26-256-B (1.2.643.7.1.2.1.1.2).
/// This does not implement the historical GOST94 hash: callers supply the
/// Streebog256 digest for a GOST2012 signature.
///
/// `digest` is the unmodified 32-byte Streebog256 output (little-endian integer).
/// `public_key` is exactly 64 bytes x_LE || y_LE, the *contents* of the DER
/// OCTET STRING inside SubjectPublicKeyInfo's BIT STRING, without DER headers.
/// `signature` is exactly 64 bytes s_BE || r_BE as in RFC 9215 section 2.
/// This only verifies a mathematical signature; no certificate trust, validity,
/// revocation, or algorithm-identifier checks are implied. Variable-time public
/// arithmetic is experimental and unaudited; no private keys are accepted.
#[must_use]
pub fn verify_cryptopro_a(digest: &[u8; 32], public_key: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 64 || signature.len() != 64 {
        return false;
    }
    let mut e = *digest;
    let mut x = [0; 32];
    let mut y = [0; 32];
    let mut r = [0; 32];
    let mut s = [0; 32];
    x.copy_from_slice(&public_key[..32]);
    y.copy_from_slice(&public_key[32..]);
    s.copy_from_slice(&signature[..32]);
    r.copy_from_slice(&signature[32..]);
    e.reverse();
    x.reverse();
    y.reverse();
    verify_integers(&e, &x, &y, &r, &s)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(value: U256) -> [u8; 32] {
        value.to_be_bytes().as_slice().try_into().expect("U256")
    }
    fn public_generator() -> [u8; 64] {
        let Point::Affine { x, y } = generator() else {
            unreachable!()
        };
        let mut result = [0; 64];
        let mut xb = bytes(x.retrieve());
        let mut yb = bytes(y.retrieve());
        xb.reverse();
        yb.reverse();
        result[..32].copy_from_slice(&xb);
        result[32..].copy_from_slice(&yb);
        result
    }
    #[test]
    fn official_rfc4357_generator_is_on_curve_and_has_declared_order() {
        let Point::Affine { x, y } = generator() else {
            unreachable!()
        };
        assert!(decode_public_key(&bytes(x.retrieve()), &bytes(y.retrieve())).is_some());
        assert_eq!(multiply(generator(), Q), Point::Infinity);
        assert_eq!(multiply(generator(), U256::ZERO), Point::Infinity);
        assert_eq!(
            add(generator(), Point::Affine { x, y: -y }),
            Point::Infinity
        );
    }
    #[test]
    fn verifies_independently_derived_public_toy_signature() {
        // Mathematical cross-check, NOT a published signature vector:
        // public test d=k=e=1, public key G, x(G)=1 => r=1, s=2.
        // All are deliberately public values; there is no signing API.
        let mut digest = [0; 32];
        digest[0] = 1;
        let mut signature = [0; 64];
        signature[31] = 2;
        signature[63] = 1;
        let key = public_generator();
        assert!(verify_cryptopro_a(&digest, &key, &signature));
        digest[0] = 2;
        assert!(!verify_cryptopro_a(&digest, &key, &signature));
        digest[0] = 1;
        signature[31] = 3;
        assert!(!verify_cryptopro_a(&digest, &key, &signature));
    }
    #[test]
    fn rejects_invalid_range_coordinates_and_encodings() {
        let key = public_generator();
        let digest = [1; 32];
        let mut sig = [0; 64];
        sig[31] = 2;
        sig[63] = 1;
        for bad in [U256::ZERO, Q, U256::MAX] {
            let mut value = sig;
            value[..32].copy_from_slice(&bytes(bad));
            assert!(!verify_cryptopro_a(&digest, &key, &value));
            let mut value = sig;
            value[32..].copy_from_slice(&bytes(bad));
            assert!(!verify_cryptopro_a(&digest, &key, &value));
        }
        assert!(!verify_cryptopro_a(&digest, &[0; 64], &sig));
        assert!(!verify_cryptopro_a(&digest, &[255; 64], &sig));
        for len in [0, 31, 32, 63] {
            assert!(!verify_cryptopro_a(&digest, &key[..len], &sig));
            assert!(!verify_cryptopro_a(&digest, &key, &sig[..len]));
        }
        // s=r, Q=G => verification point at infinity.
        sig[31] = 1;
        assert!(!verify_cryptopro_a(&digest, &key, &sig));
    }
}
