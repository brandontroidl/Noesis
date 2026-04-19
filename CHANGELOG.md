# Noesis Changelog

## 1.0.1 (2026-04-19) — Retire GameServ/WeatherBot, absorb Synaxis BotServ toys

Consolidation release to resolve command collisions with Synaxis and within Noesis itself. No functional loss — every command removed has a live home elsewhere.

### Removed
- **`modules/gameserv.go`** — standalone `GameServ` pseudo-client deleted. Its `.dice`, `.coin`, `.roulette` were duplicates of what Internets already provides (`.dice` / `.coin`) or what now lives in Internets (`.roulette`). Rizon's original acid has no GameServ; this was a Brandon-era extraction that created a double-reply problem in channels where both GameServ and Internets were present.
- **`modules/weather.go`** — standalone `WeatherBot` deleted. Rizon's actual model puts weather in Internets, which already implements `.weather <city>` and `.forecast`. Running both meant two bots responded to the same dot-command.
- Config types `WeatherModuleConfig` and `GameServConfig` removed from `config/config.go`.
- TOML stanzas `[modules.weather]` and `[modules.gameserv]` removed from `noesis.toml`.
- Module count drops 18 → 16.

### Added to Internets (migrated from Synaxis `mod-botserv.c`)
The eight BotServ toys that Synaxis shipped as assignable-per-channel commands are now native Internets commands. This removes the double-reply case where both Synaxis BotServ and Noesis Internets would answer the same `.` prefix:
- **`.d <NdM>`** — alias for `.dice`, preserving x3-BotServ muscle memory (users typing `.d 2d6` get the same result as `.dice 2d6`).
- **`.roulette`** — russian roulette with per-channel chamber state, faithful to x3's `cmd_roulette`. First pull loads (1-in-6 chamber), next pull on a loaded gun triggers the canonical `"BANG - Don't stuff bullets into a loaded gun"` message. The x3 implementation called DelUser (kill); Noesis announces only because Internets is not an operator pseudo-client. If you want kills, route through Moo/OperServ.
- **`.unf`** — `"I don't want to be part of your sick fantasies!"` (verbatim from Synaxis CSMSG_UNF_RESPONSE).
- **`.ping`** — `"Pong!"` (verbatim).
- **`.wut`** — `"wut"` (verbatim).
- **`.huggle`** — CTCP ACTION `"huggles <nick>"` in channels, `"huggles you"` in PM (verbatim).
- **`.reply <text>`** — echoes text back, prefixed with requester's nick when in a channel.
- `.calc <expr>` was already in Internets; it now effectively replaces the Synaxis BotServ `cmd_calc` too.

### Internets dispatch now 31 commands
Previously 25. The new six: `roulette`, `unf`, `ping`, `wut`, `huggle`, `reply`. (`.d` is an alias, not a new slot.)

### Runtime state change
`Internets` struct gained a `rouletteChambers map[string]int` keyed by channel for the russian roulette state machine. No persistence — chambers reset on restart, which matches x3 behavior (x3 stored in ChanData, also volatile after a restart without saxdb).

### Compatibility note
If you had `[modules.weather]` or `[modules.gameserv]` stanzas in an existing `noesis.toml`, the TOML parser will still accept them (unknown top-level tables under `[modules]` don't error) but the settings go nowhere. Safe to leave until you regenerate the config from `noesis.toml.example`; safer to delete them now.

## 1.0.0 (2026-04-19) — Rename from acid, split Aegis out

First release under the Noesis name. Identical in behavior to `acid 1.9.0` minus the abuse/monitoring layer, which now lives in the separate Aegis project.

### Renamed
- Project: `acid` → `noesis`
- Go module path: `github.com/brandontroidl/acid` → `github.com/brandontroidl/noesis`
- Default config filename: `acid.toml` → `noesis.toml`
- Binary name: `acid` → `noesis`
- CTCP VERSION reply: `"acid 1.9.0 - Cathexis P10 Services"` → `"noesis 1.0.0 - Cathexis P10 Services Framework"`
- HMAC key-derivation label (internal, for at-rest encryption): `cathexis-acid-encrypt-v1` → `cathexis-noesis-encrypt-v1`. **This is a breaking change for any encrypted storage** — old database blobs written by acid 1.x will not decrypt under noesis 1.0.0. If you rely on at-rest encryption, plan a re-key before the switch.

### Removed (moved to Aegis)
Nine module files plus their config types are now part of Aegis:
- `modules/moo.go` → `aegis/modules/moo.go`
- `modules/mod_antiidle.go` → `aegis/modules/antiidle.go`
- `modules/mod_chanlog.go` → `aegis/modules/chanlog.go`
- `modules/mod_dnsbl.go` → `aegis/modules/dnsbl.go`
- `modules/mod_mxbl.go` → `aegis/modules/mxbl.go`
- `modules/mod_osflood.go` → `aegis/modules/osflood.go`
- `modules/mod_proxyscan.go` → `aegis/modules/proxyscan.go`
- `modules/mod_track.go` → `aegis/modules/track.go`
- `modules/mod_webhooks.go` → `aegis/modules/webhooks.go`

The `Mod` prefix on their Go types has been dropped everywhere (`ModAntiIdle` → `AntiIdle`, etc.) — they are now first-class modules in Aegis, not "modifiers" of another module's behavior.

### Changed
- `modules/init.go` rewritten: registers only the 18 Noesis framework modules. Aegis manages its own registration via its own `main.go`.
- `Sentinel.SetMoo(*Moo)` field and setter removed. Sentinel no longer depends on Moo; if Aegis wants Sentinel alerts to reach oper channels, they go through Moo's normal subscription path once Aegis is running alongside.
- `modules/util.go` added with the `matchWild` glob matcher (extracted from the deleted `moo.go` so `operserv.go` still has it).
- Config struct `ModulesConfig` no longer contains fields for the moved modules. `MooConfig`, `DNSBLConfig`, `DNSBLZone`, `ProxyScanConfig`, `MXBLConfig`, `TrackConfig`, `ChanLogConfig`, `WatchConfig`, `WebhooksConfig`, `OSFloodConfig`, `AntiIdleConfig` types are gone from `config/config.go` — they live in `aegis/config/config.go` now.

### Unchanged from acid 1.9.0
FunServ broker pattern, Internets bot with 25 commands, weather-JSON-tag fix, all of 1.8.x's restored Rizon modules (xmas, quotes, trivia, weather, gameserv), all of 1.7.x's security fixes (webhook token timing, sentinel shutdown leak), all of 1.6.x and earlier behavior. Same P10 dispatch, same HMAC derivation scheme (`cathexis-s2s-hmac-v1`), same pseudo-client introduction flow.

## Pre-1.0.0 history

For versions before the rename, see the acid project's CHANGELOG. Key milestones:

- **acid 1.9.0** — FunServ rewritten as a Rizon-style broker; Internets module added.
- **acid 1.8.x** — Restored five orphan modules (xmas, quotes, trivia, weather, gameserv) after an incorrect prune; added listbots and registration ports.
- **acid 1.7.1** — Webhook token timing attack fixed; sentinel shutdown leak fixed.
- **acid 1.5.0–1.6.x** — FunServ consolidated bot, GeoIP → MaxMindDB migration.
