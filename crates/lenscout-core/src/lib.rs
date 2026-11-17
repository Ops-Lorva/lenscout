//! Lenscout core — toute la logique, sans Tauri. Les modules vides sont
//! remplis par les tâches suivantes du plan ; ils sont déclarés ici une fois
//! pour toutes afin qu'aucune tâche ne touche ce fichier.

pub mod accounts;
pub mod actions;
pub mod batch;
pub mod debug_log;
pub mod discovery;
pub mod free_ips;
pub mod http_client;
pub mod identify;
pub mod imaging;
// Code repris tel quel d'un autre projet : le lint est toléré ici.
#[allow(clippy::collapsible_if)]
pub mod interfaces;
pub mod isapi;
pub mod login_test;
pub mod migrate;
pub mod mjpeg;
pub mod model;
pub mod oui;
pub mod ops;
pub mod permissions;
pub mod presence;
pub mod proc;
pub mod route;
pub mod seal;
pub mod secret;
pub mod site_survey;
pub mod temp_ip;
pub mod transport;
pub mod vapix;
pub mod xlsx;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
