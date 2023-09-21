use borsh::{BorshDeserialize, BorshSerialize};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

// TODO To what extent should we try to mark values as secret, e.g. with mlock? Does the dalek
// library do any of that for us? Should we delegate that to users of this library? I think we
// probably should.

/// A string of bytes that is impossible to construct with any non-ASCII or non-printable
/// characters.
#[derive(Clone, Zeroize)]
pub struct PrintableAsciiString(Vec<u8>);

impl PrintableAsciiString {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        for b in bytes.iter() {
            // Characters 31 and below are nonprintable
            // Character 127 is DEL
            // Characters 128 and above are control characters
            if *b < 32 || *b > 126 {
                return None;
            }
        }
        Some(PrintableAsciiString(bytes))
    }
}

impl From<PrintableAsciiString> for String {
    fn from(s: PrintableAsciiString) -> String {
        String::from_utf8(s.0)
            .expect("ASCII should always be valid UTF-8, but this failed to convert")
    }
}

impl BorshSerialize for PrintableAsciiString {
    fn serialize<W: std::io::Write>(&self, w: &mut W) -> Result<(), std::io::Error> {
        self.0.serialize(w)
    }
}

impl BorshDeserialize for PrintableAsciiString {
    fn deserialize_reader<R: std::io::Read>(
        r: &mut R,
    ) -> Result<PrintableAsciiString, std::io::Error> {
        let bytes = <Vec<u8>>::deserialize_reader(r)?;
        Ok(
            PrintableAsciiString::from_bytes(bytes).ok_or(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unprintable characters when deserializing printable ascii string"),
            ))?,
        )
    }
}

// We use newtype wrappers for RistrettoPoint and Scalar because we need to (de)serialize them
// using Borsh. Their APIs are entirely private, and we only duplicate as much as we use.
#[derive(Clone, Copy, PartialEq, Zeroize)]
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

#[derive(Clone, Copy, PartialEq, Zeroize)]
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

#[derive(Clone, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct Signature {
    challenge: Scalar,
    ring_responses: Vec<(RistrettoPoint, Scalar)>,
}

impl Signature {
    // Sources:
    // https://web.archive.org/web/20230526135545/https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
    // (https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf)
    // https://archive.ph/rtOuB (https://github.com/edwinhere/nazgul/blob/master/src/sag.rs)
    // https://archive.ph/EsIX0 (https://github.com/zudo/ring-signature/blob/main/src/sag.rs)
    fn sign(
        message: &[u8],
        my_private_value: Scalar,
        other_public_keypoints: &[RistrettoPoint],
    ) -> Self {
        let my_public_keypoint = RistrettoPoint::mul_base(&my_private_value);

        let ring_size = other_public_keypoints.len() + 1;

        let ring = make_ring(my_public_keypoint, other_public_keypoints, |k| k);
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
                RistrettoPoint::mul_base(&responses[index]) + cs[index] * &ring[index];
        }

        responses[my_key_index] = a - (cs[my_key_index] * my_private_value);

        Self {
            challenge: cs[0],
            ring_responses: ring.into_iter().zip(responses.into_iter()).collect(),
        }
    }

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

#[derive(Clone, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct Identity {
    pub name: String,
    pub email: PrintableAsciiString, // Try to prevent homoglyph attacks in the address
}

impl Identity {
    fn bytes_for_attestation(&self, keypoint: &RistrettoPoint) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(self.name.as_bytes());
        result.extend_from_slice(&[0xff]); // sentinel separating holder name and email
        result.extend_from_slice(self.email.as_bytes());
        result.extend_from_slice(&keypoint.compress());
        result
    }
}

#[derive(Clone, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct PublicKey {
    pub holder: Identity,
    pub keypoint: RistrettoPoint,
    // We want a public key to be a simple package that can be important without additional user
    // input (e.g. associating the key with an identity). Thus the public key structure should
    // include the identity as well as the key material. But in that case, we want to make it
    // difficult for a mistaken or malicious party to cause a user to import key material with the
    // wrong identity associated.

    // This is a single-entry ring signature of the identity and the public keypoint, made by the
    // corresponding secret key. This ensures that the person with this keypair (at least) claims to have the
    // given identity. Thus a client app can refuse to import a pair that mismatches the identity
    // to the key material. And because a message signature only ensures the integrity of the
    // ring keypoints and not the associated identities, this attestation also enables enforcing that the
    // identities associated with a signed message haven't been tampered with, e.g. by an intermediary.
    pub holder_attestation: Signature,
}

impl PublicKey {
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

#[derive(Zeroize, BorshSerialize, BorshDeserialize)]
pub struct PrivateKey {
    pub holder: Identity,
    key: Scalar,
    holder_attestation: Signature, // Here b/c we don't want distinct attestations for the same keypair.
}

impl PrivateKey {
    pub fn new(holder: Identity) -> Self {
        let key = Scalar::random();
        PrivateKey {
            holder_attestation: Signature::sign(
                &holder.bytes_for_attestation(&RistrettoPoint::mul_base(&key)),
                key,
                &[],
            ),
            holder,
            key,
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

#[derive(Zeroize, BorshSerialize, BorshDeserialize)]
pub struct SignedMessage {
    message: Vec<u8>,
    challenge: Scalar,
    ring: Vec<(PublicKey, Scalar)>,
}

impl SignedMessage {
    pub fn sign(message: &[u8], my_key: &PrivateKey, other_keys: &[PublicKey]) -> Self {
        let Signature {
            challenge,
            ring_responses,
        } = Signature::sign(
            message,
            my_key.key,
            &other_keys.iter().map(|k| k.keypoint).collect::<Vec<_>>(),
        );

        let ring = make_ring(my_key.public(), other_keys, |k| k.keypoint);

        SignedMessage {
            message: message.to_vec(),
            challenge,
            ring: ring_responses
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
            challenge: self.challenge,
            ring_responses: self.ring.iter().map(|(k, s)| (k.keypoint, *s)).collect(),
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
        let signature = Signature::sign(message, my_key, &[]);
        assert!(
            signature.verify(message),
            "Failed to verify one-key signature"
        );

        let message_a = b"Message A";
        let otherkey_a = RistrettoPoint::random();
        let signature_a = Signature::sign(message_a, my_key, &[otherkey_a]);
        assert!(
            signature_a.verify(message_a),
            "Failed to verify two-key signature"
        );

        let message_b = b"Message B";
        let otherkey_b = RistrettoPoint::random();
        let signature_b = Signature::sign(message_b, my_key, &[otherkey_a, otherkey_b]);
        assert!(
            signature_b.verify(message_b),
            "Failed to verify three-key signature"
        );

        assert!(!Signature {
            ring_responses: signature_a.ring_responses.clone(),
            ..signature_b.clone()
        }
        .verify(message_b));
        assert!(!signature_b.verify(message_a));
        assert!(!Signature {
            challenge: signature_a.challenge,
            ..signature_b.clone()
        }
        .verify(message_b));
    }
}
