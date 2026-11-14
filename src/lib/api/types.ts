// Miroir exact de crates/lenscout-core/src/model.rs et interfaces.rs.

export type Family = 'axis' | 'hikvision' | 'other';
export type Activation = 'new' | 'activated' | 'unknown';
/** `http` : balayage d'un réseau routé, sans MAC (la couche 2 ne passe pas le routeur). */
export type Source = 'mdns' | 'wsd' | 'sadp' | 'oui' | 'http';
/** `null` : inconnu (le protocole ne le dit pas, ou pas de lecture avec un compte). */
export type Addressing = 'dhcp' | 'static';

export interface Camera {
  ip: string;
  mac: string | null;
  family: Family;
  brand: string | null;
  model: string | null;
  serial: string | null;
  firmware: string | null;
  activation: Activation;
  http_port: number;
  sources: Source[];
  addressing?: Addressing | null;
}

export interface InterfaceDetails {
  name: string;
  ip: string | null;
  subnet: string | null;
  gateway: string | null;
  dns: string[];
  dhcp_enabled: boolean;
  is_up: boolean;
  admin_up: boolean;
  bsd_name: string | null;
}
