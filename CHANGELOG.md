# Changelog

## Unreleased

- Automatic updates: a banner at startup; the installer is downloaded from the project's GitHub releases and launched only if its minisign signature is valid (and its version is newer). macOS, Windows and Linux releases are built and signed by CI on a `vX.Y.Z` tag.
- Application skeleton: three tabs (Network, Framing, Accounts), list of active interfaces, French / English / Spanish.
- Hikvision/LTS: SADP discovery, activation and IP change over SADP, ISAPI stream. Not verified on a real LTS camera. Activate and change IP stay disabled for Hikvision: no reliable public source for the SADP password encoding.
