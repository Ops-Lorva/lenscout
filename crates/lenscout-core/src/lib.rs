//! Lenscout core — toute la logique, sans Tauri. Les modules vides sont
//! remplis par les tâches suivantes du plan ; ils sont déclarés ici une fois
//! pour toutes afin qu'aucune tâche ne touche ce fichier.

pub mod accounts;
pub mod actions;
pub mod batch;
pub mod discovery;
pub mod http_client;
// Copié tel quel de LanProbe : on n'y touche pas, donc le lint est toléré ici.
#[allow(clippy::collapsible_if)]
pub mod interfaces;
pub mod mjpeg;
pub mod model;
pub mod oui;
pub mod permissions;
pub mod proc;
pub mod secret;
pub mod temp_ip;
pub mod transport;
pub mod vapix;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
