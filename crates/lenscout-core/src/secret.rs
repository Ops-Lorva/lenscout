use std::fmt;

use serde::{Deserialize, Deserializer};

/// Mot de passe. Pas de `Serialize` : il ne peut donc pas finir dans un
/// fichier, une réponse de commande ou un journal par accident. `Debug` et
/// `Display` n'affichent jamais la valeur. Effacé de la mémoire à sa
/// libération.
#[derive(Clone)]
pub struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl zeroize::ZeroizeOnDrop for Secret {}

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_redacted() {
        let s = Secret::new("S3cr3t-Unique!".into());
        assert!(!format!("{s:?} {s}").contains("S3cr3t"));
        assert_eq!(s.expose(), "S3cr3t-Unique!");
    }

    #[test]
    fn secret_is_wiped_when_dropped() {
        fn wiped<T: zeroize::ZeroizeOnDrop>() {}
        wiped::<Secret>();
    }
}
