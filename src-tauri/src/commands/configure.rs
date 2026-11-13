use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lenscout_core::accounts::AccountBook;
use lenscout_core::actions::{Action, ActionContext, ActionResult, apply_all, on_subnet};
use lenscout_core::discovery::arp::{ScanInterface, read_neighbours};
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
use lenscout_core::model::Camera;
use lenscout_core::temp_ip::SystemElevator;
use lenscout_core::vapix::{NetworkSettings, TimeSettings};
use serde::Deserialize;
use tauri::State;

use super::accounts::credentials_for;
use super::discovery::ScanState;

/// `<app_data_dir>/temp-ip.json` : l'IP temporaire en cours, à retirer au
/// démarrage si l'app a été tuée.
pub struct TempIpJournal(pub PathBuf);

/// Délai d'une requête d'écriture vers une caméra.
const HTTP_TIMEOUT: Duration = Duration::from_secs(8);

/// Ce que le front peut demander : des adresses déjà typées (`Ipv4Addr` refuse
/// toute autre chaîne), jamais de mot de passe.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionDto {
    Activate,
    NetworkDhcp,
    NetworkStatic {
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        #[serde(default)]
        dns: Vec<Ipv4Addr>,
    },
    Time {
        #[serde(default)]
        ntp_servers: Vec<String>,
        timezone: String,
    },
}

/// Erreurs : codes stables (`bad_action`, `iface_unknown`, `iface_no_ipv4`,
/// `not_found`, `secret_missing`, `internal`), traduits par le front. Les
/// erreurs par caméra sont dans les `ActionResult`.
pub(crate) fn to_action(dto: ActionDto) -> Result<Action, String> {
    Ok(match dto {
        ActionDto::Activate => Action::Activate,
        ActionDto::NetworkDhcp => Action::Network(NetworkSettings::Dhcp),
        ActionDto::NetworkStatic { ip, mask, gateway, dns } => {
            Action::Network(NetworkSettings::Static { ip, mask, gateway, dns })
        }
        ActionDto::Time { ntp_servers, timezone } => {
            let ntp_servers: Vec<String> = ntp_servers
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let timezone = timezone.trim().to_string();
            // Un nom de fuseau ou de serveur part tel quel dans une requête :
            // seuls les caractères d'un nom (IANA ou DNS) sont admis.
            let ok = |s: &str| {
                s.len() <= 253
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._+/:".contains(&b))
            };
            if timezone.is_empty() || !ok(&timezone) || ntp_servers.iter().any(|s| !ok(s)) {
                return Err("bad_action".into());
            }
            Action::Time(TimeSettings { ntp_servers, timezone })
        }
    })
}

/// Applique une action aux seules caméras reçues, dans l'ordre. Le front passe
/// la sélection visible ; le cœur revérifie la marque et l'identité de chaque
/// caméra avant d'écrire. Hors du sous-réseau de l'interface, une IP
/// temporaire est posée sur le poste pour une caméra vue au dernier scan.
#[tauri::command]
pub async fn cmd_apply_action(
    cameras: Vec<Camera>,
    account_id: String,
    action: ActionDto,
    iface: String,
    accounts: State<'_, Mutex<AccountBook>>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
) -> Result<Vec<ActionResult>, String> {
    let action = to_action(action)?;
    let creds = credentials_for(&accounts, &account_id)?;
    let service = iface.clone();
    let targets: Vec<Ipv4Addr> = cameras.iter().map(|c| c.ip).collect();
    let (scan_iface, any_off_subnet, other_ifaces) = tauri::async_runtime::spawn_blocking(move || {
        let up = list_interfaces_up();
        if !up.contains(&iface) {
            return Err("iface_unknown".to_string());
        }
        let scan_iface = ScanInterface::from_details(&iface, &get_interface_details(&iface))
            .ok_or_else(|| "iface_no_ipv4".to_string())?;
        // Les autres interfaces ne servent qu'au chemin hors sous-réseau :
        // leurs détails coûtent un processus chacune, on ne les lit qu'alors.
        let any_off_subnet = targets.iter().any(|ip| !on_subnet(&scan_iface, *ip));
        let others = if any_off_subnet {
            up.iter()
                .filter(|name| **name != iface)
                .filter_map(|name| ScanInterface::from_details(name, &get_interface_details(name)))
                .collect()
        } else {
            vec![]
        };
        Ok((scan_iface, any_off_subnet, others))
    })
    .await
    .map_err(|_| "internal".to_string())??;
    // Voisins ARP : jamais pris pour l'IP temporaire.
    let in_use = if any_off_subnet { read_neighbours(&scan_iface).await.into_keys().collect() } else { vec![] };
    let seen = scan.seen();
    let ctx = ActionContext {
        http: Arc::new(ReqwestCameraHttp::new(HTTP_TIMEOUT)),
        iface: scan_iface,
        service,
        elevator: Arc::new(SystemElevator),
        journal: journal.0.clone(),
        seen: seen.ips,
        seen_iface: seen.iface,
        in_use,
        other_ifaces,
    };
    Ok(apply_all(&ctx, &cameras, &creds, &action).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<Action, String> {
        to_action(serde_json::from_str::<ActionDto>(json).map_err(|_| "bad_action".to_string())?)
    }

    #[test]
    fn les_trois_actions_se_convertissent() {
        assert_eq!(parse(r#"{"kind":"activate"}"#).unwrap(), Action::Activate);
        assert_eq!(
            parse(r#"{"kind":"network_dhcp"}"#).unwrap(),
            Action::Network(NetworkSettings::Dhcp)
        );
        let net = parse(
            r#"{"kind":"network_static","ip":"192.0.2.50","mask":"255.255.255.0","gateway":null,"dns":["192.0.2.1"]}"#,
        )
        .unwrap();
        assert_eq!(
            net,
            Action::Network(NetworkSettings::Static {
                ip: "192.0.2.50".parse().unwrap(),
                mask: "255.255.255.0".parse().unwrap(),
                gateway: None,
                dns: vec!["192.0.2.1".parse().unwrap()],
            })
        );
        let t = parse(r#"{"kind":"time","ntp_servers":[" pool.ntp.org ",""],"timezone":"Europe/Paris"}"#).unwrap();
        assert_eq!(
            t,
            Action::Time(TimeSettings { ntp_servers: vec!["pool.ntp.org".into()], timezone: "Europe/Paris".into() })
        );
    }

    #[test]
    fn une_adresse_invalide_ou_un_nom_louche_est_refuse() {
        assert_eq!(
            parse(r#"{"kind":"network_static","ip":"pas-une-ip","mask":"255.255.255.0"}"#).unwrap_err(),
            "bad_action"
        );
        for bad in [
            r#"{"kind":"time","timezone":""}"#,
            r#"{"kind":"time","timezone":"Europe/Paris\"}"}"#,
            r#"{"kind":"time","timezone":"UTC","ntp_servers":["a b"]}"#,
            r#"{"kind":"time","timezone":"UTC","ntp_servers":["x&y=z"]}"#,
        ] {
            assert_eq!(parse(bad).unwrap_err(), "bad_action", "{bad}");
        }
    }
}
