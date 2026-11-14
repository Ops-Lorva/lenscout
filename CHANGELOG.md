# Changelog

## Unreleased

- The app is now named LenScout (window title, installers). Settings, accounts and logs stay where they were.
- Accounts: optional PC IP (with prefix), network and gateway, stored in clear and carried by export / import. Show / hide button on the password field.
- Network: account selector next to the interface. Choosing an account adds its PC IP to the interface (same elevation and removal as the temporary IP) and rescans; DHCP removes it. The main address, default route and interface settings are never changed.
- IP sheets: mask and gateway prefilled from the chosen account when the fields were not typed in.
- Settings moved to the bottom of the sidebar.
- Automatic updates: a banner at startup; the installer is downloaded from the project's GitHub releases and launched only if its minisign signature is valid (and its version is newer). macOS, Windows and Linux releases are built and signed by CI on a `vX.Y.Z` tag.
- Application skeleton: three tabs (Network, Framing, Accounts), list of active interfaces, French / English / Spanish.
- Hikvision/LTS: SADP discovery, activation and IP change over SADP, ISAPI stream. Not verified on a real LTS camera. Activate and change IP stay disabled for Hikvision: no reliable public source for the SADP password encoding.
