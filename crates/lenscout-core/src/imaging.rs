//! Réglages d'image d'une Axis, pour le panneau du cadrage : optique (zoom,
//! mise au point, autofocus et sa zone), rotation de la vue, correction de
//! distorsion (BDC). Tout part avec le compte ; la garde (sous-réseau ou
//! caméra routée) est à l'appelant, avant tout appel.
//!
//! Une vue `Image.I<i>` désigne son capteur par `Image.I<i>.Source` (« 0 »,
//! « 1 ») ; une vue groupée en a plusieurs (« 1,0 ») et n'a ni optique, ni
//! BDC, ni autre rotation que 0.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::transport::{CameraHttp, Credentials, NetError};
use crate::vapix::{
    FORM, VapixError, json_post, list_params, parse_json_reply, post, require_success, require_text_ok, short,
};

const OPTICS: &str = "/axis-cgi/opticscontrol.cgi";
const LENS_CAPABILITIES: &str = "/axis-cgi/lensparams/getcapabilities.cgi";
const LENS_SET_BDC: &str = "/axis-cgi/lensparams/setdistortioncorrectionmode.cgi";
/// Plus grand indice de vue accepté (`Image.I<i>`), comme `vapix::views`.
pub const MAX_VIEW_INDEX: u32 = 63;

/// Zone d'autofocus, en coordonnées normalisées de l'image (0 à 1, origine en haut à gauche).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FocusWindow {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// L'optique d'un capteur, telle que `getOptics` et `getCapabilities` la disent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Optics {
    pub id: String,
    /// 0 à 1.
    pub focus: Option<f64>,
    pub magnification: Option<f64>,
    /// `focusMoving` ou `zoomMoving` : les commandes attendent.
    pub moving: bool,
    pub window: Option<FocusWindow>,
    pub can_focus: bool,
    /// Le zoom n'est proposé que borné par `maxMagnification`.
    pub can_zoom: bool,
    pub max_magnification: Option<f64>,
}

/// Ce que le panneau peut demander à l'optique.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OpticsCommand {
    Zoom { magnification: f64 },
    Focus { position: f64 },
    Autofocus,
    FocusWindow { window: FocusWindow },
    ResetFocus,
}

/// Requête JSON d'`opticscontrol.cgi` (version majeure 1 : la caméra répond
/// à 1.0, 1.1 et 1.2).
pub fn optics_request(method: &str, params: Option<Value>) -> Value {
    let mut v = json!({"apiVersion": "1", "method": method});
    if let Some(p) = params {
        v["params"] = p;
    }
    v
}

fn unit(v: f64) -> bool {
    v.is_finite() && (0.0..=1.0).contains(&v)
}

/// Requête d'une commande pour l'optique `id`. Une valeur hors bornes (ou un
/// identifiant qui n'est pas un nombre) est refusée avant l'envoi.
pub fn command_request(id: &str, cmd: &OpticsCommand) -> Result<Value, VapixError> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VapixError::Invalid("optics_id"));
    }
    let one = |extra: Value| {
        let mut o = json!({"opticsId": id});
        if let (Some(o), Some(extra)) = (o.as_object_mut(), extra.as_object()) {
            o.extend(extra.clone());
        }
        json!({"optics": [o]})
    };
    let (method, params) = match cmd {
        OpticsCommand::Zoom { magnification: m } => {
            if !m.is_finite() || *m <= 0.0 || *m > 100.0 {
                return Err(VapixError::Invalid("magnification"));
            }
            ("setMagnification", one(json!({"magnification": m})))
        }
        OpticsCommand::Focus { position } => {
            if !unit(*position) {
                return Err(VapixError::Invalid("focus"));
            }
            ("setFocus", one(json!({"position": position})))
        }
        // `performAutofocus` dans les exemples de la doc (le tableau écrit
        // « performAutoFocus ») : la forme des exemples est retenue.
        OpticsCommand::Autofocus => ("performAutofocus", one(json!({}))),
        OpticsCommand::FocusWindow { window: w } => {
            let ok = [w.x, w.y, w.width, w.height].into_iter().all(unit)
                && w.width > 0.0
                && w.height > 0.0
                && w.x + w.width <= 1.0 + 1e-9
                && w.y + w.height <= 1.0 + 1e-9;
            if !ok {
                return Err(VapixError::Invalid("focus_window"));
            }
            ("setFocusWindow", one(json!({"upperLeftX": w.x, "upperLeftY": w.y, "width": w.width, "height": w.height})))
        }
        // La mise au point seule revient à sa position par défaut ; le zoom reste.
        OpticsCommand::ResetFocus => ("reset", one(json!({"focus": true, "zoom": false}))),
    };
    Ok(optics_request(method, Some(params)))
}

/// `data.optics` de `getOptics`.
pub fn parse_optics(v: &Value) -> Vec<Optics> {
    let Some(list) = v.pointer("/data/optics").and_then(Value::as_array) else {
        return vec![];
    };
    list.iter()
        .filter_map(|o| {
            let id = match o.get("opticsId")? {
                Value::String(s) => s.clone(),
                n @ Value::Number(_) => n.to_string(),
                _ => return None,
            };
            let num = |k: &str| o.get(k).and_then(Value::as_f64);
            let flag = |k: &str| o.get(k).and_then(Value::as_bool).unwrap_or(false);
            let window = match (num("focusWindowUpperLeftX"), num("focusWindowUpperLeftY"), num("focusWindowWidth"), num("focusWindowHeight")) {
                (Some(x), Some(y), Some(width), Some(height)) => Some(FocusWindow { x, y, width, height }),
                _ => None,
            };
            Some(Optics {
                id,
                focus: num("focusPosition").filter(|f| unit(*f)),
                magnification: num("magnification"),
                moving: flag("focusMoving") || flag("zoomMoving"),
                window,
                can_focus: num("focusPosition").is_some(),
                can_zoom: false,
                max_magnification: None,
            })
        })
        .collect()
}

/// `getCapabilities` : `capabilities` (« focus », « zoom ») et `maxMagnification`
/// de chaque optique. Le zoom n'est ouvert que borné.
pub fn apply_capabilities(optics: &mut [Optics], v: &Value) {
    let Some(list) = v.pointer("/data/optics").and_then(Value::as_array) else {
        return;
    };
    for c in list {
        let id = match c.get("opticsId") {
            Some(Value::String(s)) => s.clone(),
            Some(n @ Value::Number(_)) => n.to_string(),
            _ => continue,
        };
        let Some(o) = optics.iter_mut().find(|o| o.id == id) else { continue };
        // Une entrée sans liste de capacités ne dit rien : la lecture de getOptics reste.
        let Some(caps) = c.get("capabilities").and_then(Value::as_array) else { continue };
        let caps: Vec<&str> = caps.iter().filter_map(Value::as_str).collect();
        o.can_focus = o.focus.is_some() && caps.contains(&"focus");
        o.max_magnification = c.get("maxMagnification").and_then(Value::as_f64).filter(|m| m.is_finite() && *m > 1.0);
        o.can_zoom = caps.contains(&"zoom") && o.max_magnification.is_some() && o.magnification.is_some();
    }
}

async fn optics_call(http: &dyn CameraHttp, base: &str, creds: &Credentials, body: Value) -> Result<Value, VapixError> {
    parse_json_reply(&http.send(json_post(base, OPTICS, body), Some(creds)).await?)
}

/// L'optique `id`, lue avec ses capacités ; `None` si `opticscontrol.cgi` ne
/// répond pas (404, erreur) ou n'a pas cette optique : pas de panneau optique.
pub async fn read_optics(http: &dyn CameraHttp, base: &str, creds: &Credentials, id: &str) -> Option<Optics> {
    let v = optics_call(http, base, creds, optics_request("getOptics", None)).await.ok()?;
    let mut all = parse_optics(&v);
    if let Ok(caps) = optics_call(http, base, creds, optics_request("getCapabilities", None)).await {
        apply_capabilities(&mut all, &caps);
    }
    all.into_iter().find(|o| o.id == id)
}

/// Envoie la commande.
pub async fn send_optics(http: &dyn CameraHttp, base: &str, creds: &Credentials, id: &str, cmd: &OpticsCommand) -> Result<(), VapixError> {
    optics_call(http, base, creds, command_request(id, cmd)?).await.map(|_| ())
}

/// Relit l'optique jusqu'à la fin du mouvement, au plus `tries` lectures
/// espacées de `every` : un moteur qui ne s'arrête pas ne bloque pas le panneau.
pub async fn settle_optics(http: &dyn CameraHttp, base: &str, creds: &Credentials, id: &str, tries: usize, every: Duration) -> Option<Optics> {
    let mut last = None;
    for n in 0..tries.max(1) {
        if n > 0 {
            tokio::time::sleep(every).await;
        }
        last = read_optics(http, base, creds, id).await;
        if !last.as_ref().is_some_and(|o| o.moving) {
            break;
        }
    }
    last
}

/// Le capteur d'une vue d'après `Image.I<i>.Source` : un seul numéro ; une
/// vue groupée (« 1,0 ») n'en a pas.
pub fn sensor_of(source: &str) -> Option<u32> {
    source.trim().parse().ok()
}

/// Valeur de `root.<key>=…` dans une réponse `param.cgi`.
fn param(body: &str, key: &str) -> Option<String> {
    body.lines()
        .filter_map(|l| l.trim().split_once('='))
        .find(|(k, _)| k.trim_start_matches("root.") == key)
        .map(|(_, v)| v.trim().to_string())
}

/// Rotation d'une vue : la valeur actuelle et celles que la caméra permet.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rotation {
    pub current: u32,
    pub allowed: Vec<u32>,
}

/// `Image.I<i>.Appearance.Rotation` (dans `image`) et
/// `Properties.Image.I<i>.Rotation` (« 0,90,180,270 », dans `props`).
pub fn parse_rotation(image: &str, props: &str, i: u32) -> Option<Rotation> {
    let current = param(image, &format!("Image.I{i}.Appearance.Rotation"))?.parse().ok()?;
    let allowed: Vec<u32> = param(props, &format!("Properties.Image.I{i}.Rotation"))?
        .split(',')
        .filter_map(|r| r.trim().parse().ok())
        .filter(|r| [0, 90, 180, 270].contains(r))
        .collect();
    (!allowed.is_empty()).then_some(Rotation { current, allowed })
}

/// Paramètres d'une vue lus avec le compte : capteur(s) et rotation.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ViewParams {
    pub source: Option<String>,
    pub rotation: Option<Rotation>,
}

pub async fn read_view(http: &dyn CameraHttp, base: &str, creds: &Credentials, i: u32) -> ViewParams {
    let image = list_params(http, base, creds, &format!("Image.I{i}")).await.unwrap_or_default();
    let props = list_params(http, base, creds, &format!("Properties.Image.I{i}")).await.unwrap_or_default();
    ViewParams {
        source: param(&image, &format!("Image.I{i}.Source")).filter(|s| !s.is_empty()),
        rotation: parse_rotation(&image, &props, i),
    }
}

/// Écrit la rotation de la vue `i`, seulement si la caméra la permet (relu
/// juste avant : le front ne choisit pas la valeur écrite).
pub async fn set_rotation(http: &dyn CameraHttp, base: &str, creds: &Credentials, i: u32, degrees: u32) -> Result<(), VapixError> {
    let allowed = read_view(http, base, creds, i).await.rotation.map(|r| r.allowed).unwrap_or_default();
    if !allowed.contains(&degrees) {
        return Err(VapixError::Invalid("rotation"));
    }
    let body = format!("action=update&Image.I{i}.Appearance.Rotation={degrees}");
    require_text_ok(&http.send(post(base, "/axis-cgi/param.cgi", FORM, body), Some(creds)).await?)
}

/// Correction de distorsion (BDC) d'un capteur, d'après `getcapabilities.cgi`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Bdc {
    pub source: u32,
    pub on: bool,
    pub user_control: bool,
}

/// Corps des CGI `lensparams` (schéma 3).
pub fn lens_body(source: Option<u32>, mode: Option<bool>) -> String {
    let mut b = String::from("schemaversion=3");
    if let Some(n) = source {
        b.push_str(&format!("&imagesource={n}"));
    }
    if let Some(on) = mode {
        b.push_str(if on { "&Mode=on" } else { "&Mode=off" });
    }
    b
}

/// `attr="valeur"` dans une balise ouvrante.
fn attr(tag: &str, name: &str) -> Option<String> {
    let start = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    let end = start + tag[start..].find('"')?;
    Some(tag[start..end].to_string())
}

/// Les `<ImageSource …>` de la réponse : `currentMode` « on » ou « true »
/// vaut activé (comme la page web de la caméra), tout le reste désactivé.
pub fn parse_bdc(xml: &str) -> Vec<Bdc> {
    if xml.contains("<Error") {
        return vec![];
    }
    xml.match_indices("<ImageSource ")
        .filter_map(|(at, _)| {
            let tag = &xml[at..at + xml[at..].find('>')?];
            let mode = attr(tag, "currentMode").unwrap_or_default();
            Some(Bdc {
                source: attr(tag, "number")?.parse().ok()?,
                on: mode == "on" || mode == "true",
                user_control: attr(tag, "userControlSupported").as_deref() == Some("true"),
            })
        })
        .collect()
}

async fn lens_call(http: &dyn CameraHttp, base: &str, creds: &Credentials, path: &str, body: String) -> Result<String, VapixError> {
    let resp = http.send(post(base, path, "text/plain", body), Some(creds)).await?;
    require_success(&resp)?;
    let text = String::from_utf8_lossy(&resp.body).into_owned();
    if text.contains("<Error") {
        return Err(VapixError::Rejected(short(&text)));
    }
    Ok(text)
}

/// BDC du capteur `source`, si la caméra laisse l'utilisateur la régler.
pub async fn read_bdc(http: &dyn CameraHttp, base: &str, creds: &Credentials, source: u32) -> Option<Bdc> {
    let xml = lens_call(http, base, creds, LENS_CAPABILITIES, lens_body(None, None)).await.ok()?;
    parse_bdc(&xml).into_iter().find(|b| b.source == source && b.user_control)
}

pub async fn set_bdc(http: &dyn CameraHttp, base: &str, creds: &Credentials, source: u32, on: bool) -> Result<(), VapixError> {
    lens_call(http, base, creds, LENS_SET_BDC, lens_body(Some(source), Some(on))).await.map(|_| ())
}

/// Ce que le panneau montre pour une vue : rien de ce qui manque.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImageSettings {
    /// Capteur de la vue ; `None` pour une vue groupée.
    pub sensor: Option<u32>,
    pub optics: Option<Optics>,
    /// Seulement s'il y a un choix (plus d'une valeur permise).
    pub rotation: Option<Rotation>,
    /// `Some(activée)` seulement si le capteur la laisse régler.
    pub bdc: Option<bool>,
}

/// Capteur de la vue `i` : `Image.I<i>.Source`, sinon (caméra sans ce
/// paramètre, un seul capteur) 0 pour la première vue.
pub fn view_sensor(params: &ViewParams, i: u32) -> Option<u32> {
    match &params.source {
        Some(s) => sensor_of(s),
        None => (i == 0).then_some(0),
    }
}

pub async fn image_settings(http: &dyn CameraHttp, base: &str, creds: &Credentials, i: u32) -> ImageSettings {
    let params = read_view(http, base, creds, i).await;
    let sensor = view_sensor(&params, i);
    let (optics, bdc) = match sensor {
        Some(s) => {
            let id = s.to_string();
            let (o, b) = tokio::join!(read_optics(http, base, creds, &id), read_bdc(http, base, creds, s));
            (o.filter(|o| o.can_focus || o.can_zoom), b.map(|b| b.on))
        }
        None => (None, None),
    };
    ImageSettings { sensor, optics, rotation: params.rotation.filter(|r| r.allowed.len() > 1), bdc }
}

/// Code stable d'un échec de réglage, traduit par le front.
pub fn error_code(e: &VapixError) -> &'static str {
    match e {
        VapixError::Net(NetError::Auth | NetError::Status(401 | 403)) => "auth_failed",
        VapixError::Net(NetError::InsecureBasic) => "auth_insecure",
        VapixError::Net(NetError::Timeout | NetError::Unreachable(_) | NetError::Denied) => "unreachable",
        VapixError::Invalid(_) => "bad_value",
        _ => "setting_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use crate::testing::FakeHttp;
    use crate::transport::Method;

    const BASE: &str = "http://192.0.2.11";

    fn creds() -> Credentials {
        Credentials { login: "root".into(), password: Secret::new("pw".into()) }
    }

    /// `getOptics` réel d'une P4705-PLVE (AXIS OS 11.11), deux capteurs.
    const GET_OPTICS: &str = r#"{"apiVersion":"1.2","method":"getOptics","data":{"numberOfOptics":2,"optics":[
{"opticsId":"0","focusPosition":0.4321,"magnification":1.0,"focusMoving":false,"zoomMoving":false,
 "focusWindowUpperLeftX":0.25,"focusWindowUpperLeftY":0.25,"focusWindowWidth":0.5,"focusWindowHeight":0.5},
{"opticsId":"1","focusPosition":0.61,"magnification":1.0,"focusMoving":true,"zoomMoving":false,
 "focusWindowUpperLeftX":0.25,"focusWindowUpperLeftY":0.25,"focusWindowWidth":0.5,"focusWindowHeight":0.5}]}}"#;

    /// Forme de `getCapabilities` d'après la doc VAPIX.
    const CAPS: &str = r#"{"apiVersion":"1.2","method":"getCapabilities","data":{"numberOfOptics":2,"optics":[
{"opticsId":"0","capabilities":["focus","zoom"],"maxMagnification":2.4},
{"opticsId":"1","capabilities":["focus"]}]}}"#;

    #[test]
    fn les_requetes_json_suivent_la_doc_vapix() {
        assert_eq!(optics_request("getOptics", None), json!({"apiVersion": "1", "method": "getOptics"}));
        let r = command_request("0", &OpticsCommand::Zoom { magnification: 1.4 }).unwrap();
        assert_eq!(r, json!({"apiVersion": "1", "method": "setMagnification", "params": {"optics": [{"opticsId": "0", "magnification": 1.4}]}}));
        let r = command_request("1", &OpticsCommand::Focus { position: 0.2 }).unwrap();
        assert_eq!(r["method"], "setFocus");
        assert_eq!(r["params"]["optics"][0], json!({"opticsId": "1", "position": 0.2}));
        let r = command_request("0", &OpticsCommand::Autofocus).unwrap();
        assert_eq!(r, json!({"apiVersion": "1", "method": "performAutofocus", "params": {"optics": [{"opticsId": "0"}]}}));
        let w = FocusWindow { x: 0.25, y: 0.3, width: 0.5, height: 0.4 };
        let r = command_request("0", &OpticsCommand::FocusWindow { window: w }).unwrap();
        assert_eq!(r["method"], "setFocusWindow");
        assert_eq!(r["params"]["optics"][0], json!({"opticsId": "0", "upperLeftX": 0.25, "upperLeftY": 0.3, "width": 0.5, "height": 0.4}));
        let r = command_request("0", &OpticsCommand::ResetFocus).unwrap();
        assert_eq!(r, json!({"apiVersion": "1", "method": "reset", "params": {"optics": [{"opticsId": "0", "focus": true, "zoom": false}]}}));
    }

    #[test]
    fn une_valeur_hors_bornes_ne_part_pas() {
        for cmd in [
            OpticsCommand::Focus { position: 1.2 },
            OpticsCommand::Focus { position: f64::NAN },
            OpticsCommand::Zoom { magnification: 0.0 },
            OpticsCommand::Zoom { magnification: f64::INFINITY },
            OpticsCommand::FocusWindow { window: FocusWindow { x: 0.8, y: 0.0, width: 0.5, height: 0.5 } },
            OpticsCommand::FocusWindow { window: FocusWindow { x: 0.1, y: 0.1, width: 0.0, height: 0.5 } },
        ] {
            assert!(matches!(command_request("0", &cmd), Err(VapixError::Invalid(_))), "{cmd:?}");
        }
        assert!(command_request("0\",\"x", &OpticsCommand::Autofocus).is_err());
    }

    #[test]
    fn get_optics_se_lit_capteur_par_capteur() {
        let v: Value = serde_json::from_str(GET_OPTICS).unwrap();
        let mut o = parse_optics(&v);
        assert_eq!(o.len(), 2);
        assert_eq!((o[0].id.as_str(), o[0].focus, o[0].magnification, o[0].moving), ("0", Some(0.4321), Some(1.0), false));
        assert_eq!(o[0].window, Some(FocusWindow { x: 0.25, y: 0.25, width: 0.5, height: 0.5 }));
        assert!(o[1].moving, "focusMoving");
        // Sans getCapabilities : la mise au point oui, le zoom non (pas de borne).
        assert!(o[0].can_focus && !o[0].can_zoom);
        apply_capabilities(&mut o, &serde_json::from_str(CAPS).unwrap());
        assert!(o[0].can_zoom && o[0].max_magnification == Some(2.4));
        assert!(o[1].can_focus && !o[1].can_zoom);
    }

    #[tokio::test]
    async fn sans_opticscontrol_pas_d_optique() {
        let http = FakeHttp::new().on(Method::Post, OPTICS, 404, "");
        assert_eq!(read_optics(&http, BASE, &creds(), "0").await, None);
        let http = FakeHttp::new().on(Method::Post, OPTICS, 200, r#"{"error":{"code":1100,"message":"Internal error"}}"#);
        assert_eq!(read_optics(&http, BASE, &creds(), "0").await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn le_sondage_du_mouvement_est_borne() {
        let http = FakeHttp::new().on(Method::Post, OPTICS, 200, GET_OPTICS);
        // L'optique 1 bouge toujours : `tries` lectures, puis l'état tel quel.
        let o = settle_optics(&http, BASE, &creds(), "1", 4, Duration::from_millis(300)).await.unwrap();
        assert!(o.moving);
        let reads = http.requests().iter().filter(|r| String::from_utf8_lossy(&r.body).contains("getOptics")).count();
        assert_eq!(reads, 4);
        assert!(http.requests().iter().all(|r| r.login.as_deref() == Some("root")));
        // L'optique 0 est immobile : une lecture.
        let http = FakeHttp::new().on(Method::Post, OPTICS, 200, GET_OPTICS);
        assert!(!settle_optics(&http, BASE, &creds(), "0", 4, Duration::from_millis(300)).await.unwrap().moving);
        assert_eq!(http.requests().iter().filter(|r| String::from_utf8_lossy(&r.body).contains("getOptics")).count(), 1);
    }

    const IMAGE_I0: &str = "root.Image.I0.Enabled=yes\nroot.Image.I0.Name=Camera 1\nroot.Image.I0.Source=0\nroot.Image.I0.Appearance.Rotation=180\n";
    const PROPS_I0: &str = "root.Properties.Image.I0.Resolution=1920x1080,1280x720,640x360\nroot.Properties.Image.I0.Rotation=0,90,180,270\n";
    const IMAGE_I2: &str = "root.Image.I2.Enabled=yes\nroot.Image.I2.Name=Group View\nroot.Image.I2.Source=1,0\nroot.Image.I2.Appearance.Rotation=0\n";
    const PROPS_I2: &str = "root.Properties.Image.I2.Resolution=3840x1080,2560x720,1280x360\nroot.Properties.Image.I2.Rotation=0\n";

    #[test]
    fn rotations_permises_par_vue() {
        assert_eq!(parse_rotation(IMAGE_I0, PROPS_I0, 0), Some(Rotation { current: 180, allowed: vec![0, 90, 180, 270] }));
        assert_eq!(parse_rotation(IMAGE_I2, PROPS_I2, 2), Some(Rotation { current: 0, allowed: vec![0] }));
        assert_eq!(parse_rotation(IMAGE_I0, "", 0), None);
        assert_eq!(sensor_of("0"), Some(0));
        assert_eq!(sensor_of("1"), Some(1));
        assert_eq!(sensor_of("1,0"), None, "vue groupée");
    }

    #[tokio::test]
    async fn la_vue_groupee_n_a_ni_optique_ni_bdc_ni_rotation() {
        let http = FakeHttp::new()
            .on(Method::Get, "/axis-cgi/param.cgi?action=list&group=Image.I2", 200, IMAGE_I2)
            .on(Method::Get, "/axis-cgi/param.cgi?action=list&group=Properties.Image.I2", 200, PROPS_I2)
            .on(Method::Post, OPTICS, 200, GET_OPTICS);
        let s = image_settings(&http, BASE, &creds(), 2).await;
        assert_eq!(s, ImageSettings { sensor: None, optics: None, rotation: None, bdc: None });
        assert!(http.requests().iter().all(|r| !r.url.contains("opticscontrol")), "rien vers l'optique");
    }

    #[tokio::test]
    async fn une_vue_de_capteur_a_son_optique_sa_rotation_et_sa_bdc() {
        let http = FakeHttp::new()
            .on(Method::Get, "/axis-cgi/param.cgi?action=list&group=Image.I0", 200, IMAGE_I0)
            .on(Method::Get, "/axis-cgi/param.cgi?action=list&group=Properties.Image.I0", 200, PROPS_I0)
            .on(Method::Post, OPTICS, 200, GET_OPTICS)
            .on(Method::Post, LENS_CAPABILITIES, 200, LENS_CAPS);
        let s = image_settings(&http, BASE, &creds(), 0).await;
        assert_eq!(s.sensor, Some(0));
        assert_eq!(s.optics.unwrap().id, "0");
        assert_eq!(s.rotation.unwrap().current, 180);
        assert_eq!(s.bdc, Some(false));
    }

    #[tokio::test]
    async fn la_rotation_s_ecrit_seulement_si_elle_est_permise() {
        let http = FakeHttp::new()
            .on(Method::Get, "/axis-cgi/param.cgi?action=list&group=Image.I0", 200, IMAGE_I0)
            .on(Method::Get, "/axis-cgi/param.cgi?action=list&group=Properties.Image.I0", 200, PROPS_I0)
            .on(Method::Post, "/axis-cgi/param.cgi", 200, "OK");
        set_rotation(&http, BASE, &creds(), 0, 90).await.unwrap();
        let w = http.requests().pop().unwrap();
        assert_eq!(String::from_utf8_lossy(&w.body), "action=update&Image.I0.Appearance.Rotation=90");
        assert!(matches!(set_rotation(&http, BASE, &creds(), 0, 45).await, Err(VapixError::Invalid(_))));
        assert_eq!(http.requests().iter().filter(|r| r.method == Method::Post).count(), 1);
    }

    /// `getcapabilities.cgi` réel d'une P4705-PLVE.
    const LENS_CAPS: &str = r#"<LensParamsResponse SchemaVersion="3.0" xmlns="http://www.axis.com/vapix/http_cgi/lensparams3"><Success><GetCapabilitiesSuccess><ImageSource number="0" cropSupported="false" manualCorrectionSupported="false" currentMode="off" userControlSupported="true"></ImageSource><ImageSource number="1" cropSupported="false" manualCorrectionSupported="false" currentMode="off" userControlSupported="true"></ImageSource></GetCapabilitiesSuccess></Success></LensParamsResponse>"#;

    #[test]
    fn la_bdc_se_lit_par_capteur() {
        let b = parse_bdc(LENS_CAPS);
        assert_eq!(b, vec![Bdc { source: 0, on: false, user_control: true }, Bdc { source: 1, on: false, user_control: true }]);
        let on = LENS_CAPS.replacen("currentMode=\"off\"", "currentMode=\"true\"", 1);
        assert!(parse_bdc(&on)[0].on, "« true » vaut activé");
        let locked = LENS_CAPS.replace("userControlSupported=\"true\"", "userControlSupported=\"false\"");
        assert!(parse_bdc(&locked).iter().all(|b| !b.user_control));
        assert!(parse_bdc("<LensParamsResponse><Error><ErrorCode>10</ErrorCode></Error></LensParamsResponse>").is_empty());
        assert_eq!(lens_body(None, None), "schemaversion=3");
        assert_eq!(lens_body(Some(1), Some(true)), "schemaversion=3&imagesource=1&Mode=on");
        assert_eq!(lens_body(Some(0), Some(false)), "schemaversion=3&imagesource=0&Mode=off");
    }

    #[tokio::test]
    async fn bdc_non_reglable_ou_en_erreur() {
        let locked = LENS_CAPS.replace("userControlSupported=\"true\"", "userControlSupported=\"false\"");
        let http = FakeHttp::new().on(Method::Post, LENS_CAPABILITIES, 200, locked);
        assert_eq!(read_bdc(&http, BASE, &creds(), 0).await, None, "interrupteur caché");
        let http = FakeHttp::new().on(Method::Post, LENS_SET_BDC, 200, "<LensParamsResponse><Error><ErrorCode>20</ErrorCode></Error></LensParamsResponse>");
        assert!(matches!(set_bdc(&http, BASE, &creds(), 1, true).await, Err(VapixError::Rejected(_))));
        let req = http.requests().pop().unwrap();
        assert_eq!(String::from_utf8_lossy(&req.body), "schemaversion=3&imagesource=1&Mode=on");
        assert_eq!(req.login.as_deref(), Some("root"));
        let http = FakeHttp::new().on(Method::Post, LENS_SET_BDC, 500, "");
        assert!(set_bdc(&http, BASE, &creds(), 1, false).await.is_err());
    }
}
