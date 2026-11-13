//! Tout ce qui touche le réseau passe par ces traits ; les tests les
//! remplacent par des faux (`testing.rs`).

use std::net::SocketAddr;
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::Stream;

use crate::secret::Secret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
}

/// Un mot de passe envoyé à une caméra va dans `body`, jamais dans `url`.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub login: String,
    pub password: Secret,
}

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, NetError>> + Send>>;

#[async_trait]
pub trait CameraHttp: Send + Sync {
    async fn send(
        &self,
        req: HttpRequest,
        creds: Option<&Credentials>,
    ) -> Result<HttpResponse, NetError>;

    /// Réponse en flux ; le `body` de la `HttpResponse` rendue est vide.
    async fn stream(
        &self,
        req: HttpRequest,
        creds: Option<&Credentials>,
    ) -> Result<(HttpResponse, ByteStream), NetError>;
}

#[async_trait]
pub trait Datagram: Send + Sync {
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> Result<(), NetError>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError>;
}

#[derive(thiserror::Error, Debug)]
pub enum NetError {
    #[error("timeout")]
    Timeout,
    #[error("injoignable : {0}")]
    Unreachable(String),
    #[error("authentification refusée")]
    Auth,
    #[error("authentification Basic refusée en HTTP")]
    InsecureBasic,
    #[error("statut HTTP {0}")]
    Status(u16),
    #[error("erreur réseau : {0}")]
    Io(String),
    #[error("annulé")]
    Cancelled,
    /// Envoi refusé par le système (EPERM, EHOSTUNREACH) : sur macOS, le
    /// signe d'une permission « Réseau local » refusée à l'app.
    #[error("accès au réseau local refusé")]
    Denied,
}
