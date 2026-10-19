//! TC26-256-A parameters from RFC 7836 Appendix A.2; cofactor 4.
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::{U256, const_monty_form, const_monty_params};

const P: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
const Q: U256 =
    U256::from_be_hex("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67");
const B: U256 =
    U256::from_be_hex("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513");
const_monty_params!(
    FieldModulus,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"
);
const_monty_params!(
    ScalarModulus,
    U256,
    "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"
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
            "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
        )),
        y: Field::new(&U256::from_be_hex(
            "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
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
                    "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
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
                "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
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

/// Verify a GOST 34.10-2012 signature on TC26-256-A (OID 1.2.643.7.1.2.1.1.1).
///
/// `digest` is the unmodified 32-byte Streebog256 output (little-endian integer).
/// `public_key` is exactly 64 bytes x_LE || y_LE, the *contents* of the DER
/// OCTET STRING inside SubjectPublicKeyInfo's BIT STRING, without DER headers.
/// `signature` is exactly 64 bytes s_BE || r_BE as in RFC 9215 section 2.
/// This only verifies a mathematical signature; no certificate trust, validity,
/// revocation, or algorithm-identifier checks are implied. Variable-time public
/// arithmetic is experimental and unaudited; no private keys are accepted.
#[must_use]
pub fn verify_tc26_256_a(digest: &[u8; 32], public_key: &[u8], signature: &[u8]) -> bool {
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
    #[test]
    fn official_generator_and_public_key_have_prime_subgroup_order() {
        assert_eq!(multiply(generator(), Q), Point::Infinity);
        let x =
            U256::from_be_hex("99C3DF265EA59350640BA69D1DE04418AF3FEA03EC0F85F2DD84E8BED4952774");
        let y =
            U256::from_be_hex("E218631A69C47C122E2D516DA1C09E6BD19344D94389D1F16C0C4D4DCF96F578");
        assert!(decode_public_key(&bytes(x), &bytes(y)).is_some());
    }
    #[test]
    fn rejects_on_curve_order_two_point_and_mixed_subgroup_point() {
        // Nontrivial rational 2-torsion point (y=0). We prove the properties
        // below, rather than relying on this being an externally signed vector.
        let x =
            U256::from_be_hex("0100FE73F595FF158E974B44D478D9588744FE5C192AC47EA63075DCE7A14AAA");
        let fx = Field::new(&x);
        let a = Field::new(&U256::from_be_hex(
            "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
        ));
        assert_eq!(fx.square() * fx + a * fx + Field::new(&B), Field::ZERO);
        let torsion = Point::Affine {
            x: fx,
            y: Field::ZERO,
        };
        assert_eq!(add(torsion, torsion), Point::Infinity);
        assert_eq!(multiply(torsion, Q), torsion);
        assert!(decode_public_key(&bytes(x), &bytes(U256::ZERO)).is_none());
        let Point::Affine { x, y } = add(generator(), torsion) else {
            panic!("mixed point")
        };
        assert!(decode_public_key(&bytes(x.retrieve()), &bytes(y.retrieve())).is_none());
    }
    #[test]
    fn rejects_signature_order_boundary() {
        let Point::Affine { x, y } = generator() else {
            unreachable!()
        };
        let one = bytes(U256::ONE);
        let order = bytes(Q);
        assert!(!verify_integers(
            &one,
            &bytes(x.retrieve()),
            &bytes(y.retrieve()),
            &order,
            &one
        ));
        assert!(!verify_integers(
            &one,
            &bytes(x.retrieve()),
            &bytes(y.retrieve()),
            &one,
            &order
        ));
    }
}
