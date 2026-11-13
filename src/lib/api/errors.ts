/** Codes stables renvoyés par les commandes Rust (`Err(String)`). */
const CODES = [
  'iface_unknown',
  'iface_no_ipv4',
  'no_socket',
  'bad_ip',
  'bad_port',
  'open_failed',
  'internal',
] as const;

/** Clé i18n (sous `network.`) d'une erreur de commande ; un code inconnu reçoit le libellé générique. */
export function errorKey(e: unknown): string {
  return typeof e === 'string' && (CODES as readonly string[]).includes(e) ? `error.${e}` : 'error.unknown';
}
