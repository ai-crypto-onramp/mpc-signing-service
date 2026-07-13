//! Shamir secret sharing over a curve's scalar field, plus the proactive
//! zero-sharing used for share refresh (CMP20-style rotation).

use super::curve::Curve;

/// A share `(index, value)` where value = f(index) for the sharing polynomial.
pub type Share<C> = (u64, <C as Curve>::Scalar);

/// Split `secret` into `n` shares recoverable by any `t` of them. The sharing
/// polynomial has degree `t-1` with the secret as its constant term.
pub fn split<C: Curve>(secret: &C::Scalar, t: usize, n: usize) -> Vec<Share<C>> {
    assert!(t >= 1 && t <= n, "require 1 <= t <= n");
    let mut coeffs: Vec<C::Scalar> = Vec::with_capacity(t);
    coeffs.push(secret.clone());
    for _ in 1..t {
        coeffs.push(C::scalar_random());
    }
    eval_all::<C>(&coeffs, n)
}

/// Share a zero secret — added to existing shares to refresh them without
/// changing the reconstructed secret (proactive resharing).
pub fn split_zero<C: Curve>(t: usize, n: usize) -> Vec<Share<C>> {
    split::<C>(&C::scalar_zero(), t, n)
}

fn eval_all<C: Curve>(coeffs: &[C::Scalar], n: usize) -> Vec<Share<C>> {
    (1..=n as u64)
        .map(|i| {
            let x = C::scalar_from_u64(i);
            // Horner evaluation.
            let mut acc = C::scalar_zero();
            for c in coeffs.iter().rev() {
                acc = C::scalar_add(&C::scalar_mul(&acc, &x), c);
            }
            (i, acc)
        })
        .collect()
}

/// Reconstruct the secret from at least `t` shares via Lagrange interpolation
/// at 0. Returns `None` on duplicate indices or a non-invertible denominator.
pub fn reconstruct<C: Curve>(shares: &[Share<C>]) -> Option<C::Scalar> {
    let mut secret = C::scalar_zero();
    for (j, (xj, yj)) in shares.iter().enumerate() {
        let xj_s = C::scalar_from_u64(*xj);
        // L_j(0) = prod_{m != j} (0 - x_m) / (x_j - x_m)
        let mut num = C::scalar_one();
        let mut den = C::scalar_one();
        for (m, (xm, _)) in shares.iter().enumerate() {
            if m == j {
                continue;
            }
            let xm_s = C::scalar_from_u64(*xm);
            let neg_xm = C::scalar_sub(&C::scalar_zero(), &xm_s);
            num = C::scalar_mul(&num, &neg_xm);
            den = C::scalar_mul(&den, &C::scalar_sub(&xj_s, &xm_s));
        }
        let den_inv = C::scalar_invert(&den)?;
        let lagrange = C::scalar_mul(&num, &den_inv);
        secret = C::scalar_add(&secret, &C::scalar_mul(yj, &lagrange));
    }
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::super::curve::{Ed25519, Secp256k1};
    use super::*;

    fn split_reconstruct<C: Curve>() {
        let secret = C::scalar_random();
        let shares = split::<C>(&secret, 2, 3);
        assert_eq!(shares.len(), 3);

        // Any 2 of the 3 shares reconstruct the secret.
        for combo in [[0, 1], [0, 2], [1, 2]] {
            let subset: Vec<_> = combo.iter().map(|&i| shares[i].clone()).collect();
            let rec = reconstruct::<C>(&subset).unwrap();
            assert_eq!(C::scalar_to_bytes(&rec), C::scalar_to_bytes(&secret));
        }
    }

    fn below_threshold_wrong<C: Curve>() {
        let secret = C::scalar_random();
        let shares = split::<C>(&secret, 3, 5);
        // Fewer than t shares reconstruct to something other than the secret.
        let subset: Vec<_> = shares[..2].to_vec();
        let rec = reconstruct::<C>(&subset).unwrap();
        assert_ne!(C::scalar_to_bytes(&rec), C::scalar_to_bytes(&secret));
    }

    fn reshare_preserves_secret<C: Curve>() {
        let secret = C::scalar_random();
        let mut shares = split::<C>(&secret, 2, 3);

        // Add a zero-sharing to every share (proactive refresh).
        let delta = split_zero::<C>(2, 3);
        for (s, d) in shares.iter_mut().zip(delta.iter()) {
            assert_eq!(s.0, d.0);
            s.1 = C::scalar_add(&s.1, &d.1);
        }

        // Secret is unchanged; individual shares changed.
        let rec = reconstruct::<C>(&shares[..2]).unwrap();
        assert_eq!(C::scalar_to_bytes(&rec), C::scalar_to_bytes(&secret));
    }

    proptest::proptest! {
        // Property: for any t in 2..=n and any t-subset of the n shares, the
        // reconstructed secret equals the original.
        #[test]
        fn any_t_subset_reconstructs(t in 2usize..=5, extra in 0usize..=3, seed in proptest::prelude::any::<u64>()) {
            let n = t + extra;
            let secret = Secp256k1::scalar_from_u64(seed | 1);
            let shares = split::<Secp256k1>(&secret, t, n);
            // Rotate the starting offset to sample different t-subsets.
            let start = (seed as usize) % n;
            let subset: Vec<_> = (0..t).map(|k| shares[(start + k) % n]).collect();
            let rec = reconstruct::<Secp256k1>(&subset).unwrap();
            proptest::prop_assert_eq!(
                Secp256k1::scalar_to_bytes(&rec),
                Secp256k1::scalar_to_bytes(&secret)
            );
        }
    }

    #[test]
    fn secp256k1_shamir() {
        split_reconstruct::<Secp256k1>();
        below_threshold_wrong::<Secp256k1>();
        reshare_preserves_secret::<Secp256k1>();
    }

    #[test]
    fn ed25519_shamir() {
        split_reconstruct::<Ed25519>();
        below_threshold_wrong::<Ed25519>();
        reshare_preserves_secret::<Ed25519>();
    }
}
