use age::secrecy::SecretString;

use crate::dbfile_utils::{get_username, SERVICE_NAME};

// On Linux, it's important that this uses the SecretService backend, since the keyutils storage
// system doesn't allow for indefinite key storage. Fortunately the SecretService backend is the
// default (and I think is selected at compile time rather than runtime, based on feature flags,
// but I'm less sure about that; TODO). It would really suck to have this set up on linux and then
// keyutils just... forgets your encryption key. Not cool. Not sure what to do in that case other
// than crash or show an error indicating that we only support running under a desktop environment
// with a secret service api implementation.
#[cfg(all(not(target_os = "android"), not(feature = "debug")))]
pub(crate) fn get_or_create_db_key() -> std::io::Result<SecretString> {
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
// See https://github.com/hwchen/keyring-rs/issues/127 ; it looks like if this is implemented it
// might just store the file in app storage, which defeats the purpose in our case.
#[cfg(any(target_os = "android", feature = "debug"))]
pub(crate) fn get_or_create_db_key() -> std::io::Result<SecretString> {
    Ok(SecretString::new("".to_string()))
}
