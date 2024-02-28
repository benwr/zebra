use rand::rngs::OsRng;

use borsh::{BorshDeserialize, BorshSerialize};
use sha3::Sha3_512;
use zeroize::{Zeroize, ZeroizeOnDrop};

// We use newtype wrappers for RistrettoPoint and Scalar because we need to (de)serialize them
// using Borsh, and foreign impls aren't allowed. Their APIs stay private to this file, and
// we only duplicate as much as we use from the dalek API.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RistrettoPoint(pub(crate) curve25519_dalek::ristretto::RistrettoPoint);

// We implement Ord and PartialOrd because we use these in BTree-based containers. Note that these
// implementations use the compressed representation, and the dalek docs speicfy that "two points
// are equal if and only if their encodings are equal". Thus, these Ord/PartialOrd implementations
// are compatible with the provided Eq/PartialEq instances (the byte sequences' equality
// corresponsd to the point structs' equality).
impl Ord for RistrettoPoint {
    fn cmp(&self, rhs: &Self) -> std::cmp::Ordering {
        self.compress().cmp(&rhs.compress())
    }
}

impl PartialOrd for RistrettoPoint {
    fn partial_cmp(&self, rhs: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}

impl RistrettoPoint {
    pub(crate) fn compress(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    pub(crate) fn mul_base(s: &Scalar) -> Self {
        RistrettoPoint(curve25519_dalek::ristretto::RistrettoPoint::mul_base(&s.0))
    }

    #[cfg(test)]
    pub(crate) fn random() -> Self {
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

// We use Borsh serialization because they explicitly aim to have a bijective mapping between
// encoded types and encodings. This is a common problem with serialization formats.
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

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Scalar(curve25519_dalek::Scalar);

impl Ord for Scalar {
    fn cmp(&self, rhs: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(rhs.0.as_bytes())
    }
}

impl PartialOrd for Scalar {
    fn partial_cmp(&self, rhs: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}

impl Scalar {
    pub(crate) const ZERO: Scalar = Scalar(curve25519_dalek::Scalar::ZERO);

    pub(crate) fn from_hash(hash: Sha3_512) -> Self {
        Scalar(curve25519_dalek::Scalar::from_hash(hash))
    }

    pub(crate) fn random() -> Self {
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
