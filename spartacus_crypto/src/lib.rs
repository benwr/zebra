use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use printable_ascii::PrintableAsciiString;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
            "Could not decompress ristretto point".to_string(),
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
                "Could not deserialize ristretto scalar".to_string(),
            ),
        )?;
        Ok(Scalar(s))
    }
}

/// We make a ring of public keys. First, we add the public key corresponding to the given private
/// key to the list of possible signers. Then we sort the ring by the members' RistrettoPoints.
/// That way, all properties of the ring are determined entirely by the choice of keys, and not at
/// all by randomness.
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

#[derive(Clone, PartialEq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
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
    /// (https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf; public domain)
    /// https://archive.ph/rtOuB (https://github.com/edwinhere/nazgul/blob/master/src/sag.rs;
    /// MIT-licensed)
    /// https://archive.ph/EsIX0 (https://github.com/zudo/ring-signature/blob/main/src/sag.rs;
    /// unlicensed as far as I can tell)
    ///
    /// In writing this code, I primarily relied on Zero to Monero: Second Edition, with moderate
    /// double-checking against the first file linked above (edwinhere's SAG implementation). I
    /// glanced at the third resource linked above (zudo's impelementation) once or twice; it seems
    /// to have been written 3 months ago (as of September 2023), whereas edwinhere's version was
    /// written 3 years ago. Based on the strong similarity between the two implementations, I'd
    /// have to guess that zudo's implementation was at least inspired by edwinhere's. IMO this
    /// version is cleaner and easier-to-audit than either of theirs, due to carefully simplifying
    /// the iteration over the ring members.
    ///
    /// Copyright-wise, I'm confident that this implementation is *not* a derivative work of zudo's
    /// implementation, as I barely glanced at it to double-check my understanding of edwinhere's
    /// implementation. It's possible that this *could* be a derivative of edwinhere's
    /// implementation, though I did mainly write it from scratch. However, this may constrain me
    /// to publish this section of code under an MIT license
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

        for offset_from_my_key in 1..ring_size + 1 {
            let index = (my_key_index + offset_from_my_key) % ring_size;
            let mut hash = initial_hash.clone();
            hash.update(next_hash_update.compress());
            cs[index] = Scalar::from_hash(hash);
            next_hash_update =
                RistrettoPoint::mul_base(&responses[index]) + cs[index].clone() * &ring[index];
        }

        responses[my_key_index] = a - (cs[my_key_index].clone() * my_private_value);

        Self {
            challenge: cs[0].clone(),
            ring_responses: ring.into_iter().zip(responses).collect(),
        }
    }

    /// Verify that this is a valid signature of the given message. That is, one of the holders of
    /// the private keys corresponding to the public keys in the ring, must have produced this
    /// signature.
    fn verify(&self, message: &[u8]) -> bool {
        let initial_hash =
            hash_message_and_ring(message, self.ring_responses.iter().map(|(k, _)| k));

        let mut reconstructed_challenge = self.challenge.clone();

        for (keypoint, response) in &self.ring_responses {
            let mut h = initial_hash.clone();
            let hash_update =
                RistrettoPoint::mul_base(response) + reconstructed_challenge * keypoint;
            h.update(hash_update.compress());
            reconstructed_challenge = Scalar::from_hash(h);
        }
        self.challenge == reconstructed_challenge
    }
}

/// An identity used for creating a ring signature.
///
/// An identity always contains a name and an email address. The name can be almost any utf-8
/// string: The only exception is that it cannot contain control codes. This ensures that we can
/// cleanly serialize and deserialize it from a single line. The email address can be only ASCII
/// strings that are both printable and not spaces. This is a brute-force method for preventing
/// homoglyph attacks: In the future, we may add functionality for semi-automatically (weakly)
/// verifying public keys over email. In that case, it's important that any email address that
/// looks like a familiar one actually *is* that address and not a different one. Fortunately, even
/// email addresses in regions that primarily use alternative character sets very rarely use
/// non-ASCII characters.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, BorshSerialize)]
pub struct Identity {
    name: String,
    email: PrintableAsciiString,
}

impl Identity {
    pub fn new(name: &str, email: &str) -> Option<Self> {
        if name.contains(char::is_control) {
            return None;
        }
        Some(Self {
            name: name.to_string(),
            email: PrintableAsciiString::from_str(email).ok()?,
        })
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn email(&self) -> String {
        self.email.to_string()
    }

    /// The information that, when signed and verified, suffices to prove that the given public
    /// keypoint belongs to someone who claims this identity.
    fn bytes_for_attestation(&self, keypoint: &RistrettoPoint) -> Vec<u8> {
        let mut result = vec![];
        // This text could be anything or nothing in principle, but it's good to make it obvious
        // when a malicious source might be leading a user to make a bogus attestation.
        result.extend_from_slice(
            "!!!DO NOT SIGN THE FOLLOWING MESSAGE. DOING SO IS A SECURITY RISK. SOMEONE IS PROBABLY TRYING TO TRICK YOU!!!".as_bytes(),
        );
        result.extend_from_slice(self.name.as_bytes());
        result.extend_from_slice(&[0xff]); // sentinel separating holder's name and email. Not a
                                           // valid UTF-8 or ASCII byte.
        result.extend_from_slice(self.email.as_bytes());
        result.extend_from_slice(&keypoint.compress());
        result
    }
}

impl BorshDeserialize for Identity {
    fn deserialize_reader<R: std::io::Read>(r: &mut R) -> std::io::Result<Identity> {
        let name = String::deserialize_reader(r)?;
        let email = PrintableAsciiString::deserialize_reader(r)?;
        Identity::new(&name, email.as_str()).ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Error constructing Identity",
        ))
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
    // e.g. by an intermediary. In some sense it would be simpler to use a DSA signature instead
    // of a ring signature, but in practice that would be unnecessary extra code or an extra
    // dependency.
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

    pub fn fingerprint(&self) -> String {
        let mut buffer = vec![];
        let _ = self.serialize(&mut buffer);
        let mut res = z85::encode(Sha3_256::digest(buffer))
            .chars()
            .collect::<Vec<_>>();
        res.insert(35, ' ');
        res.insert(30, ' ');
        res.insert(25, ' ');
        res.insert(20, ' ');
        res.insert(15, ' ');
        res.insert(10, ' ');
        res.insert(5, ' ');
        res.into_iter().collect()
    }
}

impl From<PublicKey> for String {
    fn from(k: PublicKey) -> String {
        let mut buffer = vec![];
        k.holder_attestation
            .serialize(&mut buffer)
            .expect("Serialization into unbounded vec failed");
        format!(
            "[{} <{}> {} {}]",
            k.holder.name,
            k.holder.email,
            z85::encode(k.keypoint.compress()),
            z85::encode(buffer)
        )
    }
}

impl FromStr for PublicKey {
    type Err = ();
    fn from_str(s: &str) -> Result<PublicKey, ()> {
        use regex::Regex;
        let re = match Regex::new(
            r"\[([^\n]*) <([!-~]*)> ([0-9a-zA-Z.:+=^!\/*?&<>()\[\]{}@%$#-]{40}) ([0-9a-zA-Z.:+=^!\/*?&<>()\[\]{}@%$#-]{125})\]",
        ) {
            Ok(re) => re,
            Err(_) => return Err(()),
        };

        let mut caps = re.captures_iter(s).map(|c| c.extract());
        let (name, email, keypoint, attestation) = match caps.next() {
            Some((overall, [name, email, keypoint, attestation])) => {
                if overall.len() != s.len() {
                    return Err(());
                }
                (name, email, keypoint, attestation)
            }
            _ => return Err(()),
        };

        let id = Identity::new(name, email).ok_or(())?;

        let keypoint = z85::decode(keypoint).map_err(|_| ())?;
        let attestation = z85::decode(attestation).map_err(|_| ())?;

        let keypoint = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&keypoint)
            .map_err(|_| ())?
            .decompress()
            .ok_or(())?;
        let attestation = Signature::deserialize(&mut attestation.as_ref()).map_err(|_| ())?;

        let res = PublicKey {
            holder: id,
            keypoint: RistrettoPoint(keypoint),
            holder_attestation: attestation,
        };

        if !res.validate_attestation() {
            return Err(());
        }

        Ok(res)
    }
}

/// A complete private key, containing all the information required to store it to disk, or to
/// produce new ring signatures.
#[derive(Clone, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
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

    pub fn public(&self) -> PublicKey {
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
            &other_keys
                .iter()
                .map(|k| k.keypoint.clone())
                .collect::<Vec<_>>(),
        );

        let ring = make_ring(my_key.public(), other_keys, |k| k.keypoint.clone());

        SignedMessage {
            message: message.to_vec(),
            challenge: sig.challenge.clone(),
            ring: sig
                .ring_responses
                .clone()
                .into_iter()
                .zip(ring)
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
            ring_responses: self
                .ring
                .iter()
                .map(|(k, s)| (k.keypoint.clone(), s.clone()))
                .collect(),
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

    #[test]
    fn full_signatures_work() {
        let message = b"SPARTACVSSVM";
        let my_email = PrintableAsciiString::from_bytes(b"spartacus@example.com").unwrap();
        let my_name = "Spartacus";
        let my_id = Identity::new(my_name, &my_email).unwrap();
        let my_key = PrivateKey::new(my_id.clone());

        let other_email = PrintableAsciiString::from_bytes(b"notspartacus@example.com").unwrap();
        let other_name = "Gaius";
        let other_id = Identity::new(other_name, &other_email).unwrap();
        let other_key = PrivateKey::new(other_id.clone());
        let other_public = other_key.public();

        let mut signed = SignedMessage::sign(message, &my_key, &[other_public]);
        assert!(signed.verify());

        signed.message = Vec::new();
        signed.message.extend_from_slice(b"SPARTACVSEST");
        assert!(!signed.verify());
    }

    #[test]
    fn export_and_import_work() {
        let my_email = PrintableAsciiString::from_bytes(b"spartacus@example.com").unwrap();
        let my_name = "Spartacus";
        let my_id = Identity::new(my_name, &my_email).unwrap();
        let my_key = PrivateKey::new(my_id.clone());
        let export = String::from(my_key.public());
        let import = PublicKey::from_str(&export);
        let PublicKey {
            ref holder,
            ref keypoint,
            ref holder_attestation,
        } = import.unwrap();

        assert!(holder == &my_key.holder);
        assert!(keypoint == &my_key.public().keypoint);
        assert!(holder_attestation == holder_attestation);
    }
}
