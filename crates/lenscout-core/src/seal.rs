//! Scellage des identifiants dans les fichiers de l'app : XChaCha20-Poly1305
//! avec une clé intégrée au code.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

// Verrou anti-lecture, pas un secret : décision Benjamin 13/11. Le code est
// ouvert, la clé est donc publique ; elle évite seulement qu'un fichier de
// comptes se lise à l'œil ou se grep.
const KEY: [u8; 32] = [
    0xc3, 0x12, 0xce, 0xe2, 0x15, 0x75, 0xa6, 0x0e, 0x5a, 0x8b, 0x35, 0x3d, 0xe8, 0x8b, 0xc5, 0x3e,
    0x9d, 0xda, 0x75, 0x23, 0x14, 0x70, 0xaa, 0x4a, 0x4c, 0xaf, 0x42, 0x18, 0x36, 0x0a, 0xb2, 0x14,
];

const NONCE_LEN: usize = 24;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum SealError {
    #[error("scellé illisible")]
    Invalid,
}

/// `base64(nonce || chiffré)`, nonce aléatoire : deux scellages du même texte diffèrent.
pub fn seal(plain: &[u8]) -> String {
    let cipher = XChaCha20Poly1305::new(&KEY.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut out = nonce.to_vec();
    // Chiffrer en mémoire ne peut pas échouer pour une entrée de cette taille.
    out.extend(cipher.encrypt(&nonce, plain).expect("chiffrement"));
    STANDARD.encode(out)
}

pub fn open(sealed: &str) -> Result<Vec<u8>, SealError> {
    let raw = STANDARD.decode(sealed).map_err(|_| SealError::Invalid)?;
    if raw.len() < NONCE_LEN {
        return Err(SealError::Invalid);
    }
    let (nonce, data) = raw.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(&KEY.into())
        .decrypt(XNonce::from_slice(nonce), data)
        .map_err(|_| SealError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip() {
        let sealed = seal(b"S3cr3t-Unique!");
        assert!(!sealed.contains("S3cr3t"));
        assert_eq!(open(&sealed).unwrap(), b"S3cr3t-Unique!");
        assert_eq!(open(&seal(b"")).unwrap(), b"");
    }

    #[test]
    fn seal_is_randomized() {
        assert_ne!(seal(b"root"), seal(b"root"));
    }

    #[test]
    fn open_rejects_tampered() {
        let sealed = seal(b"root");
        let mut raw = STANDARD.decode(&sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert_eq!(open(&STANDARD.encode(raw)), Err(SealError::Invalid));
        assert_eq!(open("pas du base64 !"), Err(SealError::Invalid));
        assert_eq!(open("AAAA"), Err(SealError::Invalid));
    }
}
