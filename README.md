# Lenscout

Desktop app (macOS, Linux, Windows) that discovers the IP cameras on a network,
activates them, sets their IP / NTP / time zone without their web page, and
shows their stream for framing. Axis first, Hikvision / LTS next.

Tauri 2 + Rust + SvelteKit. Design: `docs/specs/2026-11-13-lenscout-design.md`.

## Installation

Download the installer for your system from the
[latest release](https://github.com/Ops-Lorva/lenscout/releases/latest):

| System | File |
|---|---|
| macOS (Apple Silicon and Intel) | `lenscout_vX.Y.Z_universal.pkg` (or `.dmg`) |
| Windows 10 / 11 | `lenscout_vX.Y.Z_x64-setup.exe` |
| Debian / Ubuntu | `lenscout_vX.Y.Z_amd64.deb` (`sudo apt install ./lenscout_vX.Y.Z_amd64.deb`) |

Lenscout checks for a newer release at startup and offers to install it. Every
installer ships with a `.sig` minisign signature, which the app verifies before
running anything it downloaded.

## Development

```bash
npm install
npx tauri dev
```

```bash
cargo test -p lenscout-core
cargo clippy --workspace -- -D warnings
npm test
```

## Layout

- `crates/lenscout-core` — all the logic, no Tauri, tested without a camera.
- `src-tauri` — thin Tauri commands.
- `src` — SvelteKit front end (fr, en, es).

## License

MIT
