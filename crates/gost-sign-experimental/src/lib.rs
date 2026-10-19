//! EXPERIMENTAL RFC 7091 section 7 mathematical proof, not a production signer.
//!
//! Supports the RFC 7091 test curve and TC26-256-A public verification.
//! No CMS, certificate trust, private-key import, or signing API.
//! Arithmetic is variable-time and must not process secrets. The deterministic
//! signing proof and its publicly published test scalars exist only in tests.
//! Reference: <https://www.rfc-editor.org/rfc/rfc7091#section-7>.

use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::{U256, const_monty_form, const_monty_params};

const P: U256 =
    U256::from_be_hex("8000000000000000000000000000000000000000000000000000000000000431");
const Q: U256 =
    U256::from_be_hex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3");
const B: U256 =
    U256::from_be_hex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E");
const_monty_params!(
    FieldModulus,
    U256,
    "8000000000000000000000000000000000000000000000000000000000000431"
);
const_monty_params!(
    ScalarModulus,
    U256,
    "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"
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
        x: Field::new(&U256::from(2u8)),
        y: Field::new(&U256::from_be_hex(
            "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",
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
            Field::new(&U256::from(3u8)) * x1.square() + Field::new(&U256::from(7u8)),
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
    if y.square() != x.square() * x + Field::new(&U256::from(7u8)) * x + Field::new(&B) {
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

/// Verify a precomputed digest using ONLY the RFC 7091 section 7 test curve.
///
/// All five inputs are unsigned 32-byte **big-endian integers**, matching the
/// mathematical values printed in the RFC. This is not a CMS signature decoder
/// or a promise about the octet ordering used by any external certificate API.
/// Invalid coordinates and out-of-range signature integers return `false`.
/// The digest integer is reduced modulo q, with zero mapped to one per RFC 7091.
/// This experimental verifier is variable-time and accepts public data only.
#[must_use]
pub fn verify_rfc7091_test_curve(
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

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(value: U256) -> [u8; 32] {
        value
            .to_be_bytes()
            .as_slice()
            .try_into()
            .expect("U256 is 32 octets")
    }
    // All values below are public RFC 7091 section 7 test data, NOT real keys.
    const D: U256 =
        U256::from_be_hex("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28");
    const K: U256 =
        U256::from_be_hex("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3");
    const E: U256 =
        U256::from_be_hex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5");
    const X: U256 =
        U256::from_be_hex("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B");
    const Y: U256 =
        U256::from_be_hex("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA");
    const R: U256 =
        U256::from_be_hex("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493");
    const S: U256 =
        U256::from_be_hex("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40");

    // Deliberately only compiled in tests. There is no public signing function.
    fn sign_published_test_values(e: U256) -> (U256, U256) {
        let Point::Affine { x, .. } = multiply(generator(), K) else {
            panic!("RFC nonce is nonzero")
        };
        let r = Scalar::new(&x.retrieve());
        let s = r * Scalar::new(&D) + Scalar::new(&K) * digest_scalar(&bytes(e));
        (r.retrieve(), s.retrieve())
    }
    fn verify(e: U256, x: U256, y: U256, r: U256, s: U256) -> bool {
        verify_rfc7091_test_curve(&bytes(e), &bytes(x), &bytes(y), &bytes(r), &bytes(s))
    }
    #[test]
    fn reproduces_rfc_public_key_and_exact_signature() {
        assert_eq!(
            multiply(generator(), D),
            decode_public_key(&bytes(X), &bytes(Y)).expect("RFC public key")
        );
        assert_eq!(sign_published_test_values(E), (R, S));
        assert!(verify(E, X, Y, R, S));
    }
    #[test]
    fn rejects_changed_digest_signature_and_public_key() {
        assert!(!verify(E ^ U256::ONE, X, Y, R, S));
        assert!(!verify(E, X, Y, R ^ U256::ONE, S));
        assert!(!verify(E, X, Y, R, S ^ U256::ONE));
        assert!(!verify(E, X ^ U256::ONE, Y, R, S));
        let Point::Affine { x, y } = generator() else {
            unreachable!()
        };
        assert!(!verify(E, x.retrieve(), y.retrieve(), R, S));
        // With Q=P and s=r, z1*P + z2*Q is infinity, not a signature.
        assert!(!verify(E, x.retrieve(), y.retrieve(), R, R));
    }
    #[test]
    fn rejects_zero_out_of_range_and_noncanonical_inputs() {
        for invalid in [U256::ZERO, Q, U256::MAX] {
            assert!(!verify(E, X, Y, invalid, S));
            assert!(!verify(E, X, Y, R, invalid));
        }
        for invalid in [P, U256::MAX] {
            assert!(!verify(E, invalid, Y, R, S));
            assert!(!verify(E, X, invalid, R, S));
        }
        assert!(!verify(E, U256::ZERO, U256::ZERO, R, S));
    }
    #[test]
    fn implements_group_identity_inverse_and_order() {
        let g = generator();
        assert_eq!(multiply(g, U256::ZERO), Point::Infinity);
        assert_eq!(multiply(g, Q), Point::Infinity);
        assert_eq!(add(Point::Infinity, g), g);
        assert_eq!(add(g, Point::Infinity), g);
        let Point::Affine { x, y } = g else {
            unreachable!()
        };
        assert_eq!(add(g, Point::Affine { x, y: -y }), Point::Infinity);
    }
    #[test]
    fn reduces_digest_and_maps_zero_to_one() {
        let (r, s) = sign_published_test_values(U256::ZERO);
        assert!(verify(U256::ZERO, X, Y, r, s));
        assert!(verify(U256::ONE, X, Y, r, s));
        assert!(verify(Q, X, Y, r, s));
    }
}

mod tc26;
pub use tc26::verify_tc26_256_a;

mod cryptopro_a;
pub use cryptopro_a::verify_cryptopro_a;
