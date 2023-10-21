use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Error as AesGcmError, Key, Nonce,
};

use std::error::Error;
use std::result::Result;

use typenum::consts::U12;
use typenum::consts::U16;

struct SymmetricSignature {
    auth_tag: Vec<u8>,
    nonce: Vec<u8>,
}

type Aes256GcmNonce = Nonce<U12>;
type Aes256GcmTag = Nonce<U16>;
type Aes256GcmKey = Key<Aes256Gcm>;

fn symm_sign(key: &Aes256GcmKey, associated_data: &[u8]) -> SymmetricSignature {
    let mut buffer = Vec::default(); // empty plaintext / ciphertext
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let cipher = Aes256Gcm::new(&key);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, associated_data, &mut buffer)
        .expect("encrypt failed");

    SymmetricSignature {
        auth_tag: tag.into_iter().collect(),
        nonce: nonce.into_iter().collect(),
    }
}

fn symm_verify(key: &Aes256GcmKey, associated_data: &[u8], symm_sig: SymmetricSignature) -> bool {
    let mut buffer = Vec::default(); // empty plaintext / ciphertext
    let nonce = Aes256GcmNonce::from_slice(symm_sig.nonce.as_slice());
    let tag = Aes256GcmTag::from_slice(symm_sig.auth_tag.as_slice());
    let cipher = Aes256Gcm::new(&key);
    let result = cipher.decrypt_in_place_detached(nonce, associated_data, buffer.as_mut(), tag);
    match result {
        Ok(()) => true,
        Err(AesGcmError) => false,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let key: Aes256GcmKey = Aes256Gcm::generate_key(OsRng);

    // good case
    {
        let associated_data = "meta informations";
        println!("associated_data for encrypt: {}", associated_data);
        let symm_sig = symm_sign(&key, associated_data.as_bytes());
        println!("associated_data for decrypt: {}", associated_data);
        let verified = symm_verify(&key, associated_data.as_bytes(), symm_sig);
        println!("verified: {}", verified);
    }

    // bad case
    {
        let mut associated_data = "meta informations";
        println!("associated_data for encrypt: {}", associated_data);
        let symm_sig = symm_sign(&key, associated_data.as_bytes());
        associated_data = "META informations";
        println!("associated_data for decrypt: {}", associated_data);
        let verified = symm_verify(&key, associated_data.as_bytes(), symm_sig);
        println!("verified: {}", verified);
    }

    Ok(())
}
