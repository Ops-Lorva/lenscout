# Changelog

## Unreleased

- Mise à jour automatique : bandeau au démarrage, installeur téléchargé depuis les releases GitHub du projet et lancé seulement si sa signature minisign est valide. Releases macOS, Windows et Linux construites et signées par la CI sur un tag `vX.Y.Z`.
- Squelette de l'application : trois onglets (Réseau, Cadrage, Comptes), liste des interfaces actives, langues fr / en / es.
- Hikvision/LTS : découverte SADP, activation et IP par SADP, flux ISAPI — non vérifiés sur une vraie caméra LTS. Activer et changer l'IP restent grisés pour Hikvision : aucune source publique fiable de l'encodage du mot de passe SADP.
