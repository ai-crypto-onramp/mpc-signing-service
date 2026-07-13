//! Curve abstraction for the threshold engine: scalar-field arithmetic (for
//! Shamir sharing), public-key derivation and aggregation (for dealer-less
//! DKG), and signing/verification. Implemented for secp256k1 (ECDSA, EVM /
//! Bitcoin) and edwards25519 (EdDSA, Solana / Aptos / Sui).

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::Scalar as EdScalar;
use ff::{Field as _, PrimeField as _};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

/// A curve's scalar field plus the point operations DKG needs. All methods
/// are associated (the type is a zero-sized marker) so Shamir code stays
/// generic over `C: Curve`.
pub trait Curve: Send + Sync + 'static {
    type Scalar: Clone + Send + Sync;

    fn name() -> &'static str;

    fn scalar_zero() -> Self::Scalar;
    fn scalar_one() -> Self::Scalar;
    fn scalar_from_u64(n: u64) -> Self::Scalar;
    fn scalar_random() -> Self::Scalar;
    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;
    fn scalar_sub(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;
    fn scalar_mul(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;
    fn scalar_invert(a: &Self::Scalar) -> Option<Self::Scalar>;
    fn scalar_to_bytes(a: &Self::Scalar) -> Vec<u8>;
    fn scalar_from_bytes(b: &[u8]) -> Option<Self::Scalar>;

    /// Compressed public key for `secret * G`.
    fn public_from_scalar(secret: &Self::Scalar) -> Vec<u8>;
    /// Sum a set of compressed public keys (for aggregating DKG commitments).
    fn aggregate_public(points: &[Vec<u8>]) -> Option<Vec<u8>>;

    /// Sign `msg` with the (reconstructed) secret scalar.
    fn sign(secret: &Self::Scalar, msg: &[u8]) -> Vec<u8>;
    /// Verify a signature against a compressed public key.
    fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}

/// secp256k1 / ECDSA.
pub struct Secp256k1;

impl Curve for Secp256k1 {
    type Scalar = k256::Scalar;

    fn name() -> &'static str {
        "secp256k1"
    }
    fn scalar_zero() -> Self::Scalar {
        k256::Scalar::ZERO
    }
    fn scalar_one() -> Self::Scalar {
        k256::Scalar::ONE
    }
    fn scalar_from_u64(n: u64) -> Self::Scalar {
        k256::Scalar::from(n)
    }
    fn scalar_random() -> Self::Scalar {
        k256::Scalar::random(&mut OsRng)
    }
    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        a + b
    }
    fn scalar_sub(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        a - b
    }
    fn scalar_mul(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        a * b
    }
    fn scalar_invert(a: &Self::Scalar) -> Option<Self::Scalar> {
        a.invert().into()
    }
    fn scalar_to_bytes(a: &Self::Scalar) -> Vec<u8> {
        a.to_repr().to_vec()
    }
    fn scalar_from_bytes(b: &[u8]) -> Option<Self::Scalar> {
        let arr: [u8; 32] = b.try_into().ok()?;
        k256::Scalar::from_repr(arr.into()).into_option()
    }
    fn public_from_scalar(secret: &Self::Scalar) -> Vec<u8> {
        let point = k256::ProjectivePoint::GENERATOR * secret;
        point.to_affine().to_encoded_point(true).as_bytes().to_vec()
    }
    fn aggregate_public(points: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut acc = k256::ProjectivePoint::IDENTITY;
        for p in points {
            let pk = k256::PublicKey::from_sec1_bytes(p).ok()?;
            acc += pk.to_projective();
        }
        Some(acc.to_affine().to_encoded_point(true).as_bytes().to_vec())
    }
    fn sign(secret: &Self::Scalar, msg: &[u8]) -> Vec<u8> {
        use k256::ecdsa::signature::Signer;
        let sk = k256::ecdsa::SigningKey::from_bytes(&secret.to_repr())
            .expect("nonzero reconstructed scalar");
        let sig: k256::ecdsa::Signature = sk.sign(msg);
        sig.to_vec()
    }
    fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use k256::ecdsa::signature::Verifier;
        let Ok(vk) = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else {
            return false;
        };
        let Ok(sig) = k256::ecdsa::Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}

/// edwards25519 / EdDSA (Schnorr over Ed25519; signatures verify with the
/// standard Ed25519 verifier).
pub struct Ed25519;

impl Curve for Ed25519 {
    type Scalar = EdScalar;

    fn name() -> &'static str {
        "ed25519"
    }
    fn scalar_zero() -> Self::Scalar {
        EdScalar::ZERO
    }
    fn scalar_one() -> Self::Scalar {
        EdScalar::ONE
    }
    fn scalar_from_u64(n: u64) -> Self::Scalar {
        EdScalar::from(n)
    }
    fn scalar_random() -> Self::Scalar {
        EdScalar::random(&mut OsRng)
    }
    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        a + b
    }
    fn scalar_sub(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        a - b
    }
    fn scalar_mul(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        a * b
    }
    fn scalar_invert(a: &Self::Scalar) -> Option<Self::Scalar> {
        Some(a.invert())
    }
    fn scalar_to_bytes(a: &Self::Scalar) -> Vec<u8> {
        a.to_bytes().to_vec()
    }
    fn scalar_from_bytes(b: &[u8]) -> Option<Self::Scalar> {
        let arr: [u8; 32] = b.try_into().ok()?;
        Some(EdScalar::from_bytes_mod_order(arr))
    }
    fn public_from_scalar(secret: &Self::Scalar) -> Vec<u8> {
        (ED25519_BASEPOINT_TABLE * secret)
            .compress()
            .to_bytes()
            .to_vec()
    }
    fn aggregate_public(points: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut acc = curve25519_dalek::edwards::EdwardsPoint::default();
        for p in points {
            let arr: [u8; 32] = p.as_slice().try_into().ok()?;
            let point = CompressedEdwardsY(arr).decompress()?;
            acc += point;
        }
        Some(acc.compress().to_bytes().to_vec())
    }
    fn sign(secret: &Self::Scalar, msg: &[u8]) -> Vec<u8> {
        // EdDSA/Schnorr with the shared scalar. A verifiable signature does
        // not depend on RFC 8032's seed-based nonce derivation, so this
        // verifies under the standard Ed25519 verifier.
        let a_bytes = (ED25519_BASEPOINT_TABLE * secret).compress().to_bytes();
        let r = EdScalar::random(&mut OsRng);
        let r_point = (ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();
        let mut h = Sha512::new();
        h.update(r_point);
        h.update(a_bytes);
        h.update(msg);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&h.finalize());
        let k = EdScalar::from_bytes_mod_order_wide(&wide);
        let s = r + k * secret;
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&r_point);
        sig.extend_from_slice(&s.to_bytes());
        sig
    }
    fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use ed25519_dalek::Verifier as _;
        let Ok(pk_arr) = <[u8; 32]>::try_from(public_key) else {
            return false;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
            return false;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };
        vk.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig_arr))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_scalar<C: Curve>() {
        let s = C::scalar_random();
        let bytes = C::scalar_to_bytes(&s);
        let back = C::scalar_from_bytes(&bytes).unwrap();
        assert_eq!(C::scalar_to_bytes(&back), bytes);
    }

    fn field_axioms<C: Curve>() {
        let a = C::scalar_from_u64(7);
        let b = C::scalar_from_u64(11);
        // a * a^-1 = 1
        let inv = C::scalar_invert(&a).unwrap();
        assert_eq!(
            C::scalar_to_bytes(&C::scalar_mul(&a, &inv)),
            C::scalar_to_bytes(&C::scalar_one())
        );
        // a + b - b = a
        let s = C::scalar_sub(&C::scalar_add(&a, &b), &b);
        assert_eq!(C::scalar_to_bytes(&s), C::scalar_to_bytes(&a));
        // zero is additive identity
        assert_eq!(
            C::scalar_to_bytes(&C::scalar_add(&a, &C::scalar_zero())),
            C::scalar_to_bytes(&a)
        );
    }

    fn sign_verify<C: Curve>() {
        let s = C::scalar_random();
        let pk = C::public_from_scalar(&s);
        let sig = C::sign(&s, b"threshold message");
        assert!(C::verify(&pk, b"threshold message", &sig));
        assert!(!C::verify(&pk, b"different message", &sig));
    }

    fn aggregate_is_sum<C: Curve>() {
        // pub(a) + pub(b) == pub(a+b)
        let a = C::scalar_random();
        let b = C::scalar_random();
        let agg =
            C::aggregate_public(&[C::public_from_scalar(&a), C::public_from_scalar(&b)]).unwrap();
        let direct = C::public_from_scalar(&C::scalar_add(&a, &b));
        assert_eq!(agg, direct);
    }

    #[test]
    fn secp256k1_curve() {
        roundtrip_scalar::<Secp256k1>();
        field_axioms::<Secp256k1>();
        sign_verify::<Secp256k1>();
        aggregate_is_sum::<Secp256k1>();
    }

    #[test]
    fn ed25519_curve() {
        roundtrip_scalar::<Ed25519>();
        field_axioms::<Ed25519>();
        sign_verify::<Ed25519>();
        aggregate_is_sum::<Ed25519>();
    }
}
