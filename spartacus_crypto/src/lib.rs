use borsh::{BorshDeserialize, BorshSerialize};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use printable_ascii::PrintableAsciiString;

// TODO To what extent should we try to mark values as secret, e.g. with mlock? Does the dalek
// library do any of that for us? Should we delegate that to users of this library? I think we
// probably should. For now we use the Zeroize crate to at least ensure that secrets are *usually*
// zeroed.

// TODO right now, throughout here we use the OsRng willy-nilly, rather than aiming to be generic
// over PRNGs. If we want to add property testing, or if someone else wants to use this library for
// something else in the future, we should change this.

// We use newtype wrappers for RistrettoPoint and Scalar because we need to (de)serialize them
// using Borsh. Their APIs stay private to this file, and we only duplicate as much as we use from
// the dalek API.
#[derive(Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct RistrettoPoint(curve25519_dalek::ristretto::RistrettoPoint);

impl RistrettoPoint {
    fn compress(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    fn mul_base(s: &Scalar) -> Self {
        RistrettoPoint(curve25519_dalek::ristretto::RistrettoPoint::mul_base(&s.0))
    }

    #[cfg(test)]
    fn random() -> Self {
        RistrettoPoint(curve25519_dalek::ristretto::RistrettoPoint::random(
            &mut OsRng,
        ))
    }
}

impl std::ops::Add<RistrettoPoint> for RistrettoPoint {
    type Output = RistrettoPoint;

    fn add(self, p: RistrettoPoint) -> Self::Output {
        RistrettoPoint(self.0 + p.0)
    }
}

impl BorshSerialize for RistrettoPoint {
    fn serialize<W: std::io::Write>(&self, w: &mut W) -> Result<(), std::io::Error> {
        self.compress().serialize(w)
    }
}

impl BorshDeserialize for RistrettoPoint {
    fn deserialize_reader<R: std::io::Read>(r: &mut R) -> Result<RistrettoPoint, std::io::Error> {
        let bytes = <[u8; 32]>::deserialize_reader(r)?;
        let compressed_point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&bytes)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Could not deserialize ristretto point: {e:?}"),
                )
            })?;
        let point = compressed_point.decompress().ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Could not decompress ristretto point"),
        ))?;
        Ok(RistrettoPoint(point))
    }
}

#[derive(Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Scalar(curve25519_dalek::Scalar);

impl Scalar {
    const ZERO: Scalar = Scalar(curve25519_dalek::Scalar::ZERO);

    fn from_hash(hash: Sha3_512) -> Self {
        Scalar(curve25519_dalek::Scalar::from_hash(hash))
    }

    fn random() -> Self {
        Scalar(curve25519_dalek::Scalar::random(&mut OsRng))
    }
}

impl std::ops::Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, s: Scalar) -> Self::Output {
        Scalar(self.0 * s.0)
    }
}

impl std::ops::Mul<&RistrettoPoint> for Scalar {
    type Output = RistrettoPoint;

    fn mul(self, p: &RistrettoPoint) -> Self::Output {
        RistrettoPoint(self.0 * p.0)
    }
}

impl std::ops::Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, s: Scalar) -> Self::Output {
        Scalar(self.0 - s.0)
    }
}

impl BorshSerialize for Scalar {
    fn serialize<W: std::io::Write>(&self, w: &mut W) -> Result<(), std::io::Error> {
        self.0.as_bytes().serialize(w)
    }
}

impl BorshDeserialize for Scalar {
    fn deserialize_reader<R: std::io::Read>(r: &mut R) -> Result<Scalar, std::io::Error> {
        let bytes = <[u8; 32]>::deserialize_reader(r)?;
        let s = Option::from(curve25519_dalek::Scalar::from_canonical_bytes(bytes)).ok_or(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Could not deserialize ristretto scalar"),
            ),
        )?;
        Ok(Scalar(s))
    }
}

/// We make a ring of public keys. First, we add the public key corresponding to the given private
/// key to the list of possible signers. Then we sort the ring by the members' RistrettoPoints.
/// That way, all properties of the ring are determined entirely by the choice of keys, and not at
/// all by randomness.

// TODO Is there a reason that the other ECC-based implementations I've found prefer to shuffle the
// ring, rather than sorting it? I can't immediately think of a reason, and in RSA-based code I've
// seen, the reverse is true.
fn make_ring<T: Clone, F: Fn(T) -> RistrettoPoint>(
    my_key: T,
    other_keys: &[T],
    key_extractor: F,
) -> Vec<T> {
    let ring_size = other_keys.len() + 1;
    let mut ring = Vec::with_capacity(ring_size);
    ring.extend_from_slice(other_keys);
    ring.push(my_key.clone());
    ring.sort_by_key(|k| key_extractor(k.clone()).compress());
    ring
}

/// Generate the hash of the message and public keys in the ring. This serves as the mathematical
/// object that is actually "signed" in the ring signature.
fn hash_message_and_ring<'a>(
    message: &[u8],
    keys: impl Iterator<Item = &'a RistrettoPoint>,
) -> Sha3_512 {
    let mut message_and_ring_hash = Sha3_512::new_with_prefix(message);
    for keypoint in keys {
        message_and_ring_hash.update(keypoint.compress())
    }
    message_and_ring_hash
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct Signature {
    challenge: Scalar,
    ring_responses: Vec<(RistrettoPoint, Scalar)>,
}

impl Signature {
    /// Compute a ring signature of the given message, using the given private key, such that the
    /// signature could have been produced by any of the holders of the given public keys (those
    /// passed in directly, or the one that can be generated from the given private key).
    ///
    /// Sources:
    /// https://web.archive.org/web/20230526135545/https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
    /// (https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf)
    /// https://archive.ph/rtOuB (https://github.com/edwinhere/nazgul/blob/master/src/sag.rs)
    /// https://archive.ph/EsIX0 (https://github.com/zudo/ring-signature/blob/main/src/sag.rs)
    fn sign(
        message: &[u8],
        my_private_value: Scalar,
        other_public_keypoints: &[RistrettoPoint],
    ) -> Self {
        let my_public_keypoint = RistrettoPoint::mul_base(&my_private_value);

        let ring_size = other_public_keypoints.len() + 1;

        let ring = make_ring(my_public_keypoint.clone(), other_public_keypoints, |k| k);
        let my_key_index = ring
            .binary_search_by_key(&my_public_keypoint.compress(), |k| k.compress())
            .expect("Key just inserted into vec, but missing after sorting.");

        let mut responses: Vec<Scalar> = (0..ring_size).map(|_| Scalar::random()).collect();
        let mut cs: Vec<Scalar> = vec![Scalar::ZERO; ring_size];

        let a = Scalar::random();
        let initial_hash = hash_message_and_ring(message, ring.iter());
        let mut next_hash_update = RistrettoPoint::mul_base(&a);

        for offset_from_my_key in 0..ring_size {
            let index = (my_key_index + offset_from_my_key + 1) % ring_size;
            let mut hash = initial_hash.clone();
            hash.update(next_hash_update.compress());
            cs[index] = Scalar::from_hash(hash);
            next_hash_update =
                RistrettoPoint::mul_base(&responses[index]) + cs[index].clone() * &ring[index];
        }

        responses[my_key_index] = a - (cs[my_key_index].clone() * my_private_value);

        Self {
            challenge: cs[0].clone(),
            ring_responses: ring.into_iter().zip(responses.into_iter()).collect(),
        }
    }

    /// Verify that this is a valid signature of the given message. That is, one of the holders of
    /// the private keys corresponding to the public keys in the ring, must have produced this
    /// signature.
    fn verify(&self, message: &[u8]) -> bool {
        let initial_hash =
            hash_message_and_ring(&message, self.ring_responses.iter().map(|(k, _)| k));

        let mut reconstructed_challenge = self.challenge.clone();

        for (keypoint, response) in &self.ring_responses {
            let mut h = initial_hash.clone();
            let hash_update =
                RistrettoPoint::mul_base(&response) + reconstructed_challenge * keypoint;
            h.update(hash_update.compress());
            reconstructed_challenge = Scalar::from_hash(h);
        }
        self.challenge == reconstructed_challenge
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct Identity {
    pub name: String,
    pub email: PrintableAsciiString, // Try to prevent homoglyph attacks in the address
}

impl Identity {
    /// The information that, when signed and verified, suffices to prove that the given public
    /// keypoint belongs to someone who claims this identity.
    fn bytes_for_attestation(&self, keypoint: &RistrettoPoint) -> Vec<u8> {
        let mut result = vec![];
        // This text could be anything or nothing in principle, but it's good to make it obvious
        // when a malicious source might be leading a user to make a bogus attestation.
        result.extend_from_slice("I AM SPARTACUS. I VERIFY THAT THE KEY BELOW BELONGS TO: ".as_bytes());
        result.extend_from_slice(self.name.as_bytes());
        result.extend_from_slice(&[0xff]); // sentinel separating holder's name and email. Not a
                                           // valid UTF-8 or ASCII byte.
        result.extend_from_slice(self.email.as_bytes());
        result.extend_from_slice(&keypoint.compress());
        result
    }
}

/// A complete public key, containing all the information required to share the key with others, to
/// store it to disk, or to take part in a ring signature or verification.
#[derive(Clone, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct PublicKey {
    pub holder: Identity,
    pub keypoint: RistrettoPoint,
    // We want a public key to be a simple package that can be imported into an app without
    // additional user input (e.g. associating the key with an identity). Thus the public key
    // structure should include the identity as well as the key material. But in that case, we want
    // to make it difficult for a mistaken or malicious party to cause a user to import key
    // material with the wrong identity associated.

    // This is a single-entry ring signature of the identity and the public keypoint, made by the
    // corresponding secret key. This ensures that the person with this keypair (at least) claims
    // to have the given identity. Thus a client app can refuse to import a pair that mismatches
    // the identity to the key material. And because a message signature only ensures the integrity
    // of the ring keypoints and not the associated identities, this attestation also enables
    // enforcing that the identities associated with a signed message haven't been tampered with,
    // e.g. by an intermediary.
    pub holder_attestation: Signature,
}

impl PublicKey {
    /// Verify that the holder of this public key's corresponding private key has claimed that the
    /// key belongs to the identity that this key appears with.
    fn validate_attestation(&self) -> bool {
        if self.holder_attestation.ring_responses.len() != 1 {
            return false;
        }
        if self.holder_attestation.ring_responses[0].0 != self.keypoint {
            return false;
        }
        self.holder_attestation
            .verify(&self.holder.bytes_for_attestation(&self.keypoint))
    }
}


/// A complete private key, containing all the information required to store it to disk, or to
/// produce new ring signatures.
#[derive(Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct PrivateKey {
    pub holder: Identity,
    key: Scalar,
    // We store the holder attestation in the private key as well as the public key, because we
    // don't want to generate distinct attestations for the same keypair: Because each attestation
    // includes a randomly-generated challenge, each independently-generated attestation will be
    // different. Cryptographicall this shouldn't matter, but it's nice to have only one canonical
    // public key rather than an endless stream of them.
    holder_attestation: Signature,
}

impl PrivateKey {
    pub fn new(holder: Identity) -> Self {
        let key = Scalar::random();
        PrivateKey {
            holder_attestation: Signature::sign(
                &holder.bytes_for_attestation(&RistrettoPoint::mul_base(&key)),
                key.clone(),
                &[],
            ),
            holder,
            key: key.clone(),
        }
    }

    fn public(&self) -> PublicKey {
        PublicKey {
            holder: self.holder.clone(),
            keypoint: RistrettoPoint::mul_base(&self.key),
            holder_attestation: self.holder_attestation.clone(),
        }
    }
}

/// A signed message. Contains enough information to verify that one of a given set of public keys
/// signed the included message (and that those keys claim to correspond to the given identities).
#[derive(Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct SignedMessage {
    message: Vec<u8>,
    challenge: Scalar,
    ring: Vec<(PublicKey, Scalar)>,
}

impl SignedMessage {
    pub fn sign(message: &[u8], my_key: &PrivateKey, other_keys: &[PublicKey]) -> Self {
        let sig = Signature::sign(
            message,
            my_key.key.clone(),
            &other_keys.iter().map(|k| k.keypoint.clone()).collect::<Vec<_>>(),
        );

        let ring = make_ring(my_key.public(), other_keys, |k| k.keypoint.clone());

        SignedMessage {
            message: message.to_vec(),
            challenge: sig.challenge.clone(),
            ring: sig.ring_responses.clone()
                .into_iter()
                .zip(ring.into_iter())
                .map(|((_, s), p)| (p, s))
                .collect(),
        }
    }

    pub fn verify(&self) -> bool {
        // 1. Verify that the public key attestations are valid
        for (k, _) in self.ring.iter() {
            if !k.validate_attestation() {
                return false;
            }
        }

        // 2. Verify the signature itself
        self.signature().verify(&self.message)
    }

    fn signature(&self) -> Signature {
        Signature {
            challenge: self.challenge.clone(),
            ring_responses: self.ring.iter().map(|(k, s)| (k.keypoint.clone(), s.clone())).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_signatures_work() {
        let message = b"Message";
        let my_key = Scalar::random();
        let signature = Signature::sign(message, my_key.clone(), &[]);
        assert!(
            signature.verify(message),
            "Failed to verify one-key signature"
        );

        let message_a = b"Message A";
        let otherkey_a = RistrettoPoint::random();
        let signature_a = Signature::sign(message_a, my_key.clone(), &[otherkey_a.clone()]);
        assert!(
            signature_a.verify(message_a),
            "Failed to verify two-key signature"
        );

        let message_b = b"Message B";
        let otherkey_b = RistrettoPoint::random();
        let signature_b = Signature::sign(message_b, my_key, &[otherkey_a.clone(), otherkey_b]);
        assert!(
            signature_b.verify(message_b),
            "Failed to verify three-key signature"
        );

        assert!(!Signature {
            ring_responses: signature_a.ring_responses.clone(),
            challenge: signature_b.challenge.clone(),
        }
        .verify(message_b));
        assert!(!signature_b.verify(message_a));
        assert!(!Signature {
            challenge: signature_a.challenge.clone(),
            ring_responses: signature_b.ring_responses.clone(),
        }
        .verify(message_b));
    }
}
