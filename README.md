# Lenscout

Desktop app (macOS, Linux, Windows) that discovers the IP cameras on a network,
activates them, sets their IP / NTP / time zone without their web page, and
shows their stream for framing. Axis first, Hikvision / LTS next.

Tauri 2 + Rust + SvelteKit. Design: `docs/specs/2026-11-13-lenscout-design.md`.

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
