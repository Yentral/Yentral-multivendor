use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength { expected: usize, got: usize },

    #[error("invalid fingerprint format")]
    InvalidFingerprint,

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("post-quantum key generation failed")]
    PqKeyGen,

    #[error("signature verification failed")]
    BadSignature,
}
