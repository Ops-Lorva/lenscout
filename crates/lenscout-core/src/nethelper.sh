#!/bin/bash
# lenscout-nethelper : posé par Lenscout (root:wheel 0755) en même temps que
# sa règle sudoers, seul programme que cette règle autorise. Il ne fait
# confiance à aucun argument et revalide tout lui-même :
#
#   add <service source> <ip> <masque>
#       duplique le service source (présent et actif) en « Lenscout », lui
#       donne ip/masque (routeur = ip), puis le place en dernier dans l'ordre
#       des services, recalculé ici depuis l'ordre courant : la route par
#       défaut ne change pas. IP privée RFC 1918 ou lien local, masque
#       contigu de /8 à /30.
#   remove
#       retire le service « Lenscout ».
#
# Bash 3.2 (celui de macOS) : ni tableaux associatifs ni mapfile.
set -u
set -f
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
NS='@NETWORKSETUP@'
SVC=Lenscout

die() {
  echo "lenscout-nethelper: $1" >&2
  exit 2
}

# Une commande networksetup, sa sortie recopiée ; elle rend parfois 0 en
# écrivant « ** Error ».
ns() {
  local out rc
  out=$("$NS" "$@" 2>&1)
  rc=$?
  if [ -n "$out" ]; then printf '%s\n' "$out"; fi
  case "$out" in *"** Error"*) rc=1 ;; esac
  return $rc
}

# IPv4 décimale pointée stricte (sans zéro en tête) → entier.
ip_num() {
  local re='^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$'
  local i o n=0
  [[ $1 =~ $re ]] || return 1
  for i in 1 2 3 4; do
    o=${BASH_REMATCH[$i]}
    [ "$o" -le 255 ] || return 1
    n=$(( n * 256 + o ))
  done
  echo "$n"
}

# Longueur d'un masque contigu.
mask_prefix() {
  local m=$1 p=0
  while [ $p -lt 32 ] && [ $(( (m >> (31 - p)) & 1 )) -eq 1 ]; do
    p=$(( p + 1 ))
  done
  [ "$m" -eq $(( (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF )) ] || return 1
  echo "$p"
}

# 10/8, 172.16/12, 192.168/16 ou 169.254/16.
private_or_link_local() {
  local n=$1
  [ $(( n >> 24 )) -eq 10 ] && return 0
  [ $(( n >> 20 )) -eq $(( (172 << 4) | 1 )) ] && return 0
  [ $(( n >> 16 )) -eq $(( (192 << 8) | 168 )) ] && return 0
  [ $(( n >> 16 )) -eq $(( (169 << 8) | 254 )) ] && return 0
  return 1
}

trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

cmd_add() {
  [ $# -eq 3 ] || die "usage : add <service> <ip> <masque>"
  local src=$1 ip mask prefix net bcast line name found=0
  ip=$(ip_num "$2") || die "adresse invalide"
  mask=$(ip_num "$3") || die "masque invalide"
  prefix=$(mask_prefix "$mask") || die "masque non contigu"
  { [ "$prefix" -ge 8 ] && [ "$prefix" -le 30 ]; } || die "masque hors /8 à /30"
  private_or_link_local "$ip" || die "adresse ni privée ni lien local"
  net=$(( ip & mask ))
  bcast=$(( net | (~mask & 0xFFFFFFFF) ))
  { [ "$ip" -ne "$net" ] && [ "$ip" -ne "$bcast" ]; } || die "adresse réseau ou diffusion"
  case "$src" in
    '' | -* | \** | "$SVC") die "service source refusé" ;;
  esac
  # Service source : une ligne exacte de la liste (un « * » en tête = désactivé).
  while IFS= read -r line; do
    if [ "$line" = "$src" ]; then found=1; fi
  done <<< "$("$NS" -listallnetworkservices 2>/dev/null)"
  [ $found -eq 1 ] || die "service source inconnu"
  # Ordre courant, lu avant la pose : « (1) Wi-Fi », « (*) … » = désactivé.
  # Bash 3.2 sous `set -u` : un tableau vide se compte à part.
  local order=() count=0
  local re='^\(([0-9]+|\*)\) (.*)$'
  while IFS= read -r line; do
    if [[ $line =~ $re ]]; then
      name=$(trim "${BASH_REMATCH[2]}")
      if [ -n "$name" ] && [ "$name" != "$SVC" ]; then order+=("$name"); count=$(( count + 1 )); fi
    fi
  done <<< "$("$NS" -listnetworkserviceorder 2>/dev/null)"
  [ $count -gt 0 ] || die "ordre des services illisible"
  ns -duplicatenetworkservice "$src" "$SVC" || exit 1
  ns -setmanual "$SVC" "$2" "$3" "$2" || exit 1
  ns -ordernetworkservices "${order[@]}" "$SVC" || exit 1
}

cmd_remove() {
  [ $# -eq 0 ] || die "usage : remove"
  ns -removenetworkservice "$SVC" || exit 1
}

case "${1:-}" in
  add) shift; cmd_add "$@" ;;
  remove) shift; cmd_remove "$@" ;;
  *) die "usage : add <service> <ip> <masque> | remove" ;;
esac
