use borsh::{BorshDeserialize, BorshSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string of bytes that is impossible to construct with any non-ASCII, non-printable, or
/// whitespace characters. This is mainly useful as a brute-force solution to avoid homoglyph
/// attacks.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    BorshSerialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct BoringAscii(Vec<u8>);

impl BoringAscii {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("BoringAscii was somehow invalid")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        for b in bytes.iter() {
            // Characters 31 and below are nonprintable
            // Character 32 is SPC
            // Character 127 is DEL
            // Characters 128 and above are control characters
            if *b < 33 || *b > 126 {
                return None;
            }
        }
        Some(BoringAscii(bytes.to_vec()))
    }
}

/* BEGIN IMPLS THAT CAN CONSTRUCT A PRINTABLEASCIISTRING */
// These should all (indirectly) call `from_bytes`.

impl std::str::FromStr for BoringAscii {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // from_bytes checks that bytes are inside the printable ASCII range, which excludes
        // multibyte codepoints, and thus anything unexpected.
        Self::from_bytes(s.as_bytes()).ok_or(())
    }
}

impl TryFrom<&str> for BoringAscii {
    type Error = <BoringAscii as std::str::FromStr>::Err;
    fn try_from(s: &str) -> Result<BoringAscii, Self::Error> {
        <BoringAscii as std::str::FromStr>::from_str(s)
    }
}

// We serialize to a series of bytes, which means that on deserialization we just have to do the
// exact same range check as we do on from_bytes.
impl BorshDeserialize for BoringAscii {
    fn deserialize_reader<R: std::io::Read>(r: &mut R) -> Result<BoringAscii, std::io::Error> {
        let bytes = <Vec<u8>>::deserialize_reader(r)?;
        BoringAscii::from_bytes(&bytes).ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unprintable characters when deserializing (supposedly) printable ascii string"
                .to_string(),
        ))
    }
}

/* END IMPLEMENTATIONS THAT CAN CONSTRUCT A PRINTABLEASCIISTRING */

impl std::fmt::Display for BoringAscii {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// We implement Deref, Borrow, and AsRef, but never DerefMut, BorrowMut, or AsMut, to ensure that
// users can't change the bytes directly.
impl std::ops::Deref for BoringAscii {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for BoringAscii {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for BoringAscii {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<Vec<u8>> for BoringAscii {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl std::borrow::Borrow<str> for BoringAscii {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl std::borrow::Borrow<[u8]> for BoringAscii {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::borrow::Borrow<Vec<u8>> for BoringAscii {
    fn borrow(&self) -> &Vec<u8> {
        &self.0
    }
}

impl From<BoringAscii> for String {
    fn from(s: BoringAscii) -> String {
        String::from_utf8(s.0.clone())
            .expect("ASCII should always be valid UTF-8, but this failed to convert")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert!(BoringAscii::from_bytes("😊".as_bytes()) == None);
        assert!(BoringAscii::from_bytes(&[b'\0']) == None);
        assert!(BoringAscii::from_bytes(&[b'\x7f']) == None);
        assert!(BoringAscii::from_bytes(&[b'\x1f']) == None);
        assert!(BoringAscii::from_bytes(&[b' ']) == None);
        assert!(BoringAscii::from_bytes(&[b'\n']) == None);
        assert!(BoringAscii::from_bytes("Hi".as_bytes()) == Some(BoringAscii(b"Hi".to_vec())));
        assert!(BoringAscii::from_bytes(&[b'!']) == Some(BoringAscii(b"!".to_vec())));
    }
}
