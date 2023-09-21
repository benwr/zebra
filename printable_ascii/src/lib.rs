use borsh::{BorshDeserialize, BorshSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string of bytes that is impossible to construct with any non-ASCII or non-printable
/// characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PrintableAsciiString(Vec<u8>);

impl PrintableAsciiString {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        for b in bytes.iter() {
            // Characters 31 and below are nonprintable
            // Character 127 is DEL
            // Characters 128 and above are control characters
            if *b < 32 || *b > 126 {
                return None;
            }
        }
        Some(PrintableAsciiString(bytes.to_vec()))
    }
}

impl From<PrintableAsciiString> for String {
    fn from(s: PrintableAsciiString) -> String {
        String::from_utf8(s.0.clone())
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
            PrintableAsciiString::from_bytes(&bytes).ok_or(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unprintable characters when deserializing printable ascii string"),
            ))?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert!(PrintableAsciiString::from_bytes("😊".as_bytes()) == None);
        assert!(PrintableAsciiString::from_bytes(&[b'\0']) == None);
        assert!(PrintableAsciiString::from_bytes(&[b'\x7f']) == None);
        assert!(PrintableAsciiString::from_bytes(&[b'\x1f']) == None);
        assert!(PrintableAsciiString::from_bytes("Hi".as_bytes()) == Some(PrintableAsciiString(b"Hi".to_vec())));
        assert!(PrintableAsciiString::from_bytes(&[b' ']) == Some(PrintableAsciiString(b" ".to_vec())));
    }
}
