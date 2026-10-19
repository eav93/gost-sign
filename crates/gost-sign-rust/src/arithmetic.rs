//! Fixed-schedule Jacobian adapter over RustCrypto modular arithmetic.
//! EFD add-2007-bl / dbl-2007-bl; exceptional cases selected with subtle.
//! https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
//! Not independently audited; no claim about generated machine-code timing.
use crate::{Error, Result};
use crypto_bigint::{U256, const_monty_form, const_monty_params, modular::ConstMontyParams};
use gost_sign_core::verification::Gost256Curve;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;
const_monty_params!(
    P,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"
);
const_monty_params!(
    Qa,
    U256,
    "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"
);
const_monty_params!(
    Qb,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"
);
const_monty_form!(F, P);
const_monty_form!(Sa, Qa);
const_monty_form!(Sb, Qb);
#[derive(Clone, Copy)]
struct Point {
    x: F,
    y: F,
    z: F,
}
impl Point {
    const ZERO: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        z: F::ZERO,
    };
    fn select(a: Self, b: Self, choice: Choice) -> Self {
        Self {
            x: F::conditional_select(&a.x, &b.x, choice),
            y: F::conditional_select(&a.y, &b.y, choice),
            z: F::conditional_select(&a.z, &b.z, choice),
        }
    }
    fn double(self, a: F) -> Self {
        let xx = self.x.square();
        let yy = self.y.square();
        let yyyy = yy.square();
        let zz = self.z.square();
        let s = ((self.x + yy).square() - xx - yyyy).double();
        let m = xx.double() + xx + a * zz.square();
        let x = m.square() - s.double();
        Self {
            x,
            y: m * (s - x) - yyyy.double().double().double(),
            z: (self.y + self.z).square() - yy - zz,
        }
    }
    fn add(self, rhs: Self, a: F) -> Self {
        let z1z1 = self.z.square();
        let z2z2 = rhs.z.square();
        let u1 = self.x * z2z2;
        let u2 = rhs.x * z1z1;
        let s1 = self.y * rhs.z * z2z2;
        let s2 = rhs.y * self.z * z1z1;
        let h = u2 - u1;
        let i = h.double().square();
        let j = h * i;
        let r = (s2 - s1).double();
        let v = u1 * i;
        let x = r.square() - j - v.double();
        let ordinary = Self {
            x,
            y: r * (v - x) - (s1 * j).double(),
            z: ((self.z + rhs.z).square() - z1z1 - z2z2) * h,
        };
        let equal_x = u1.ct_eq(&u2);
        let equal_y = s1.ct_eq(&s2);
        let result = Self::select(ordinary, Self::ZERO, equal_x & !equal_y);
        let result = Self::select(result, self.double(a), equal_x & equal_y);
        let result = Self::select(result, rhs, self.z.ct_eq(&F::ZERO));
        Self::select(result, self, rhs.z.ct_eq(&F::ZERO))
    }
    fn bytes(self) -> [u8; 64] {
        let inverse = self.z.invert().unwrap_or(F::ZERO);
        let x = self.x * inverse.square();
        let y = self.y * inverse.square() * inverse;
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(x.retrieve().to_le_bytes().as_slice());
        bytes[32..].copy_from_slice(y.retrieve().to_le_bytes().as_slice());
        bytes
    }
}
fn parameters(curve: Gost256Curve) -> (F, Point, U256) {
    let (a, x, y, q) = match curve {
        Gost256Curve::Tc26A => (
            "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
            "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
            "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
            U256::from_be_hex("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
        ),
        Gost256Curve::CryptoProA => (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
            U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
        ),
    };
    (
        F::new(&U256::from_be_hex(a)),
        Point {
            x: F::new(&U256::from_be_hex(x)),
            y: F::new(&U256::from_be_hex(y)),
            z: F::ONE,
        },
        q,
    )
}
fn multiply(curve: Gost256Curve, scalar: &U256) -> Point {
    let (a, generator, _) = parameters(curve);
    let mut result = Point::ZERO;
    let bytes: Zeroizing<[u8; 32]> =
        Zeroizing::new(scalar.to_be_bytes().as_slice().try_into().expect("U256"));
    for byte in bytes.iter() {
        for bit in (0..8).rev() {
            let doubled = result.double(a);
            let added = doubled.add(generator, a);
            result = Point::select(doubled, added, Choice::from((byte >> bit) & 1));
        }
    }
    result
}
pub(crate) fn public(curve: Gost256Curve, key: &[u8; 32]) -> Result<[u8; 64]> {
    let d = Zeroizing::new(U256::from_le_slice(key));
    let (_, _, q) = parameters(curve);
    if *d == U256::ZERO || *d >= q {
        return Err(Error("Закрытый ключ вне допустимого диапазона"));
    }
    Ok(multiply(curve, &d).bytes())
}
fn with_nonce(
    curve: Gost256Curve,
    key: &[u8; 32],
    digest: &[u8; 32],
    k: &U256,
) -> Option<[u8; 64]> {
    let point = multiply(curve, k).bytes();
    let x = U256::from_le_slice(&point[..32]);
    macro_rules! calculate {
        ($s:ty) => {{
            let d = <$s>::new(&U256::from_le_slice(key));
            let e = <$s>::new(&U256::from_le_slice(digest));
            let e = <$s>::conditional_select(&e, &<$s>::ONE, e.ct_eq(&<$s>::ZERO));
            let r = <$s>::new(&x);
            let s = r * d + <$s>::new(k) * e;
            if bool::from(r.ct_eq(&<$s>::ZERO) | s.ct_eq(&<$s>::ZERO)) {
                return None;
            }
            let mut output = [0; 64];
            output[..32].copy_from_slice(s.retrieve().to_be_bytes().as_slice());
            output[32..].copy_from_slice(r.retrieve().to_be_bytes().as_slice());
            Some(output)
        }};
    }
    match curve {
        Gost256Curve::Tc26A => calculate!(Sa),
        Gost256Curve::CryptoProA => calculate!(Sb),
    }
}
pub(crate) fn sign(curve: Gost256Curve, key: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 64]> {
    let (_, _, q) = parameters(curve);
    for _ in 0..1024 {
        let mut random = Zeroizing::new([0; 32]);
        getrandom::fill(random.as_mut())
            .map_err(|_| Error("Не удалось получить случайные байты ОС"))?;
        let k = Zeroizing::new(U256::from_le_slice(random.as_ref()));
        if *k == U256::ZERO || *k >= q {
            continue;
        }
        if let Some(signature) = with_nonce(curve, key, digest, &k) {
            return Ok(signature);
        }
    }
    Err(Error("Не удалось сформировать случайный параметр подписи"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_boundaries_and_random_signatures() {
        for curve in [Gost256Curve::Tc26A, Gost256Curve::CryptoProA] {
            let (a, g, q) = parameters(curve);
            assert_eq!(multiply(curve, &U256::ONE).bytes(), g.bytes());
            assert!(bool::from(multiply(curve, &q).z.ct_eq(&F::ZERO)));
            assert!(bool::from(multiply(curve, &U256::ZERO).z.ct_eq(&F::ZERO)));
            assert_eq!(g.add(g, a).bytes(), g.double(a).bytes());
            assert!(bool::from(
                g.add(
                    Point {
                        x: g.x,
                        y: -g.y,
                        z: g.z
                    },
                    a
                )
                .z
                .ct_eq(&F::ZERO)
            ));
            let last = q.wrapping_sub(&U256::ONE);
            assert_eq!(
                multiply(curve, &last).bytes(),
                Point {
                    x: g.x,
                    y: -g.y,
                    z: g.z
                }
                .bytes()
            );
            let boundary: [u8; 32] = last.to_le_bytes().as_slice().try_into().expect("scalar");
            let pk = public(curve, &boundary).expect("q-1 key");
            let sig =
                with_nonce(curve, &boundary, &[0; 32], &U256::from(2u8)).expect("zero digest");
            assert!(match curve {
                Gost256Curve::Tc26A =>
                    gost_sign_experimental::verify_tc26_256_a(&[0; 32], &pk, &sig),
                Gost256Curve::CryptoProA =>
                    gost_sign_experimental::verify_cryptopro_a(&[0; 32], &pk, &sig),
            });
            assert!(public(curve, &[0; 32]).is_err());
            assert!(public(curve, &[255; 32]).is_err());
            let mut key = [0; 32];

            key[0] = 1;
            for _ in 0..12 {
                let mut d = [0; 32];
                getrandom::fill(&mut d).expect("RNG");
                let sig = sign(curve, &key, &d).expect("sign");
                let pk = public(curve, &key).expect("public");
                let valid = match curve {
                    Gost256Curve::Tc26A => gost_sign_experimental::verify_tc26_256_a(&d, &pk, &sig),
                    Gost256Curve::CryptoProA => {
                        gost_sign_experimental::verify_cryptopro_a(&d, &pk, &sig)
                    }
                };
                assert!(valid);
                getrandom::fill(&mut key).expect("RNG");
                key[31] &= 0x3f;
            }
        }
    }
}
