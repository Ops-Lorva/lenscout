/** Codes stables renvoyés par les commandes Rust (`Err(String)`). */
const CODES = [
  'iface_unknown',
  'iface_no_ipv4',
  'no_socket',
  'local_network_denied',
  'bad_ip',
  'bad_port',
  'bad_action',
  'preview_unknown',
  'preview_expired',
  'no_cameras',
  'open_failed',
  'empty_field',
  'duplicate_name',
  'camera_off_subnet',
  'unsupported_brand',
  'unreachable',
  'auth_failed',
  'auth_insecure',
  'stream_failed',
  'not_found',
  'secret_missing',
  'keyring',
  'io',
  'internal',
] as const;

/** Clé i18n (sous l'espace de la page appelante) d'une erreur de commande ; un code inconnu reçoit le libellé générique. */
export function errorKey(e: unknown): string {
  return typeof e === 'string' && (CODES as readonly string[]).includes(e) ? `error.${e}` : 'error.unknown';
}
