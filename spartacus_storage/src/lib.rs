use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use borsh::{BorshDeserialize, BorshSerialize};
use directories::ProjectDirs;
use fs2::FileExt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use printable_ascii::PrintableAsciiString;
use spartacus_crypto::{Identity, PrivateKey, PublicKey, SignedMessage};

// Databases will be "human-sized", i.e. almost always have less than 100 private keys and less
// than 10,000 public keys. Each public key is ~40 bytes for the identity, plus 32 bytes for the
// keypoint, plus 96 for the attestation and 72 for the verification info, for a total of <250
// bytes, which means 10,000 of them are <3MiB. As a result, I currently expect that the best
// method for storing things is to simply write the whole db to disk on every change, into a
// temporary file, and then move it to overwrite the existing db file when writing is complete.
// This should roughly ensure that the db is never in a bad state, even if the computer crashes or
// loses power. Only about 112 of those 250 bytes are compressible at all, so we can get at most a
// 50% improvement in file size by adding compression. I think we should at least skip it for now,
// and probably just never worry about it.

const SERVICE_NAME: &str = "Spartacus";

pub struct Database {
    db_path: PathBuf,
    // We keep this open to ensure that the lock stays held
    _lockedfile: File,
    // We don't store sensitive information (private keys) in memory if we can avoid it
    pub visible_contents: VisibleDatabaseContents,
}

#[derive(Clone, BorshDeserialize, BorshSerialize, Zeroize, ZeroizeOnDrop)]
pub struct VerificationInfo {
    // None if unverified
    // If verified, the i64 is the unix timestamp (in UTC) at which verification was completed.
    verified_date: Option<i64>,
}

impl VerificationInfo {
    fn now() -> Self {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Self {
            verified_date: Some(now),
        }
    }
    fn unverified() -> Self {
        Self {
            verified_date: None,
        }
    }
    pub fn is_verified(&self) -> bool {
        self.verified_date.is_some()
    }
    pub fn verified_time(&self) -> Option<time::OffsetDateTime> {
        self.verified_date
            .and_then(|stamp| time::OffsetDateTime::from_unix_timestamp(stamp).ok())
    }
}

#[derive(Default, BorshDeserialize, BorshSerialize, Zeroize, ZeroizeOnDrop)]
struct DatabaseContentsV0 {
    private_keys: Vec<PrivateKey>,
    public_keys: Vec<(PublicKey, VerificationInfo)>,
}

#[derive(BorshDeserialize, BorshSerialize, Zeroize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
enum SpartacusDatabaseContents {
    V0(DatabaseContentsV0) = 0,
}

impl Default for SpartacusDatabaseContents {
    fn default() -> Self {
        Self::V0(DatabaseContentsV0 {
            private_keys: vec![],
            public_keys: vec![],
        })
    }
}

#[derive(Default)]
pub struct VisibleDatabaseContents {
    pub my_public_keys: Vec<PublicKey>,
    pub their_public_keys: Vec<(PublicKey, VerificationInfo)>,
}

impl DatabaseContentsV0 {
    fn get_visible(&self) -> VisibleDatabaseContents {
        let DatabaseContentsV0 {
            private_keys,
            public_keys,
        } = self;
        VisibleDatabaseContents {
            my_public_keys: private_keys.iter().map(|k| k.public()).collect(),
            their_public_keys: public_keys.to_vec(),
        }
    }
}

fn get_username() -> String {
    let mut result = whoami::username();
    if result.is_empty() {
        result = "spartacus_user".to_string();
    }
    result
}

#[cfg(not(target_os = "android"))]
fn get_or_create_db_key() -> std::io::Result<SecretString> {
    let entry = match keyring::Entry::new(SERVICE_NAME, &get_username()) {
        Ok(entry) => entry,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        }
    };
    match entry.get_password() {
        Ok(pw) => Ok(SecretString::new(pw)),
        Err(keyring::error::Error::NoEntry) => {
            use rand::distributions::DistString;
            let pw = rand::distributions::Alphanumeric.sample_string(&mut rand::rngs::OsRng, 32);
            match entry.set_password(&pw) {
                Ok(()) => Ok(SecretString::new(pw)),
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )),
            }
        }
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        )),
    }
}

// NOTE: If keyring ever supports the android keystore, we should (carefully!) update this.
#[cfg(target_os = "android")]
fn get_or_create_db_key() -> std::io::Result<SecretString> {
    Ok(SecretString::new("".to_string()))
}

impl Database {
    pub fn new<P: AsRef<Path> + std::fmt::Debug>(path: P) -> std::io::Result<Self> {
        if let Some(p) = path.as_ref().parent() {
            std::fs::create_dir_all(p)?;
        }
        let _lockedfile = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(lockfile_path(&path))?;
        // we never return this lock. The operating system will release it when the file is closed, as
        // the program dies.
        _lockedfile.try_lock_exclusive()?;

        let contents = Self::get_contents(&path)?;

        Ok(Self {
            _lockedfile,
            visible_contents: contents.0.get_visible(),
            db_path: path.as_ref().to_path_buf(),
        })
    }

    fn get_contents<P: AsRef<Path> + std::fmt::Debug>(
        path: &P,
    ) -> std::io::Result<(DatabaseContentsV0, SecretString)> {
        let pw = get_or_create_db_key()?;

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)?;

        if file.metadata()?.len() == 0 {
            return Ok((DatabaseContentsV0::default(), pw));
        }

        let mut reader = match age::Decryptor::new(&file) {
            Ok(age::Decryptor::Passphrase(dec)) => match dec.decrypt(&pw, None) {
                Ok(reader) => reader,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ));
                }
            },
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Database seems to be encrypted wrong",
                ));
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ));
            }
        };

        use std::io::Read;
        let mut bytes = vec![];
        // We've already authenticated this file, since age is AEAD. So we can be relatively sure
        // that it's not crafted to DoS us.
        reader.read_to_end(&mut bytes)?;
        let SpartacusDatabaseContents::V0(res) =
            BorshDeserialize::deserialize(&mut bytes.as_ref())?;
        Ok((res, pw))
    }

    fn write_contents(&mut self, db: DatabaseContentsV0, pw: SecretString) -> std::io::Result<()> {
        use std::io::Write;

        let result_vis = db.get_visible();

        let mut buffer = vec![];
        SpartacusDatabaseContents::V0(db).serialize(&mut buffer)?;

        let mut tmpfile = tempfile::NamedTempFile::new()?;
        let encryptor = age::Encryptor::with_user_passphrase(pw);

        let mut writer = match encryptor.wrap_output(&mut tmpfile) {
            Ok(w) => w,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            }
        };
        writer.write_all(&buffer)?;
        writer.finish()?;

        let f = tmpfile.persist(&self.db_path)?;
        f.sync_all()?;
        self.visible_contents = result_vis;
        Ok(())
    }

    pub fn sign(
        &self,
        message: &[u8],
        my_key_index: usize,
        other_key_indexes: &[usize],
    ) -> std::io::Result<SignedMessage> {
        let (contents, _) = Self::get_contents(&self.db_path)?;
        let my_key = contents.private_keys[my_key_index].clone();
        let mut other_keys = Vec::with_capacity(other_key_indexes.len() + 1);
        for i in other_key_indexes {
            other_keys.push(contents.public_keys[*i].0.clone())
        }
        Ok(SignedMessage::sign(message, &my_key, &other_keys))
    }

    pub fn set_verified(&mut self, public_key_index: usize) -> std::io::Result<()> {
        let (mut contents, pw) = Self::get_contents(&self.db_path)?;
        contents.public_keys[public_key_index].1 = VerificationInfo::now();
        self.write_contents(contents, pw)
    }

    pub fn set_unverified(&mut self, public_key_index: usize) -> std::io::Result<()> {
        let (mut contents, pw) = Self::get_contents(&self.db_path)?;
        contents.public_keys[public_key_index].1 = VerificationInfo::unverified();
        self.write_contents(contents, pw)
    }

    pub fn add_public_keys(&mut self, public_keys: &[PublicKey]) -> std::io::Result<()> {
        let (mut contents, pw) = Self::get_contents(&self.db_path)?;
        contents.public_keys.extend(
            public_keys
                .iter()
                .map(|k| (k.clone(), VerificationInfo::unverified()))
                .collect::<Vec<_>>(),
        );
        self.write_contents(contents, pw)
    }

    pub fn delete_public_key(&mut self, index: usize) -> std::io::Result<()> {
        let (mut contents, pw) = Self::get_contents(&self.db_path)?;
        contents.public_keys.remove(index);
        self.write_contents(contents, pw)
    }

    pub fn new_private_key(
        &mut self,
        name: &str,
        email: &PrintableAsciiString,
    ) -> std::io::Result<()> {
        let identity = Identity::new(name, email).ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Could not construct Identity",
        ))?;
        let key = PrivateKey::new(identity);
        self.import_private_key(key)
    }

    pub fn import_private_key(&mut self, key: PrivateKey) -> std::io::Result<()> {
        let (mut contents, pw) = Self::get_contents(&self.db_path)?;
        contents.private_keys.push(key);
        self.write_contents(contents, pw)
    }

    pub fn export_private_key(&mut self, index: usize) -> std::io::Result<PrivateKey> {
        let (contents, _) = Self::get_contents(&self.db_path)?;
        Ok(contents.private_keys[index].clone())
    }

    pub fn delete_private_key(&mut self, index: usize) -> std::io::Result<()> {
        let (mut contents, pw) = Self::get_contents(&self.db_path)?;
        contents.private_keys.remove(index);
        self.write_contents(contents, pw)
    }
}

fn app_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("me", "w-r", SERVICE_NAME) {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::new()
    }
}

pub fn default_db_path() -> PathBuf {
    app_dir().join("spartacus_db.age")
}

fn lockfile_path<P: AsRef<Path>>(p: &P) -> PathBuf {
    p.as_ref().with_extension("lock")
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn it_works() {}
}
