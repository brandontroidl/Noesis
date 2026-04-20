# Noesis Changelog

## 1.1.0 (2026-04-19) — Cathexis 1.6.0 alignment + Sentinel DNSBL scoring

Matches the Cathexis 1.6.0 post-quantum s2s crypto upgrade. Adds weighted DNSBL reputation scoring to the Sentinel abuse-detection module.

### S2S cryptography — HMAC-SHA3-512 (breaking)
`server/s2s_crypto.go` is rewritten to default to the `cathexis-s2s-hmac-sha3-v2` scheme:
- **Key derivation**: HKDF-SHA3-512 (replaces HMAC-SHA256 as the KDF)
- **Per-message tag**: HMAC-SHA3-512, 64-byte / 128-hex-char output (was HMAC-SHA256 / 32-byte / 64-hex)
- **Labels**: `cathexis-s2s-hmac-sha3-v2` and `cathexis-s2s-sacert-sha3-v2` (was `cathexis-s2s-hmac-v1` / `sacert-v1`)
- **Challenge binding**: challenge bound into HKDF `info` field so derived keys can't be replayed across challenges

Legacy v1 (HMAC-SHA256) is retained as an explicit opt-in scheme. Set `hmac_scheme = "cathexis-s2s-hmac-v1"` in the `[network]` stanza of `noesis.toml` during transition windows when linking to a pre-1.6.0 Cathexis. Default (empty scheme) is v2.

**Interop**: Noesis 1.1.0 talks to Cathexis 1.6.0+ only when both use v2. During migration either set the scheme override, or upgrade Cathexis → Synaxis → Noesis in close sequence.

### New dependency
`golang.org/x/crypto v0.28.0` for `sha3` and `hkdf` packages (Go 1.22's stdlib doesn't include these yet; 1.24+ would). Run `go mod tidy` on first build.

### Sentinel — weighted DNSBL scoring
`modules/sentinel.go` now parses Cathexis 1.5.6+ extended DNSBL marks (`DNSBL|zone1|zone2|...`), sums per-zone weights from `[modules.sentinel.dnsbl_scoring]`, and drives automated response:
- **score ≥ gline_threshold** → GLINE the IP for `dnsbl_gline_duration` seconds
- **score ≥ warn_threshold** → NOTICE to `alert_channel`
- **score < warn_threshold** → log-only

Zones not in the weights table default to weight 1. Set a zone to weight 0 to observe without contributing to the score (useful for noisy RBLs you want to track but not act on). The `[modules.sentinel.dnsbl_scoring.descriptions]` map provides human-readable zone labels for logs and alert messages.

Default thresholds in `noesis.toml.example`: warn=3, gline=7, gline duration=3600s, with DroneBL weighted 3, EFnet RBL + Tor exit list + Cerberus each weighted 2.

### Server dispatch fix
`server/server.go` routes MARK commands to all modules (previously swallowed before module dispatch). `HandleMessage` in Sentinel fast-paths MARK to the new `handleDNSBLMark` parser when the DNSBL score path is enabled.

### CTCP VERSION
`modules/ctcp.go` — reply bumped to `"noesis 1.1.0 - Cathexis P10 Services Framework"`.

### Config additions (`noesis.toml.example`)
```toml
[modules.sentinel]
enabled = true
alert_channel = "#opers"
dnsbl_warn_threshold = 3
dnsbl_gline_threshold = 7
dnsbl_gline_duration = 3600
dnsbl_gline_reason = "…"
dnsbl_mark_prefix = "DNSBL"

[modules.sentinel.dnsbl_scoring]
"dnsbl.dronebl.org" = 3
"rbl.efnetrbl.org"  = 2
"torexit.dan.me.uk" = 2

[modules.sentinel.dnsbl_scoring.descriptions]
# optional human labels for each zone
```

### Migration
1. Build: `go mod tidy && go build ./...`
2. If Cathexis peer is still pre-1.6.0: add `hmac_scheme = "cathexis-s2s-hmac-v1"` to your `[network]` stanza until the peer upgrades
3. If Cathexis peer is already 1.6.0 (recommended path): default (empty) scheme works; no config change needed
4. DNSBL weights are opt-in — module works with Cathexis's existing `DNSBL_MARK` feature. Extended marks (`DNSBL|zone|zone|...`) require Cathexis 1.5.6+; older Cathexis emits the bare prefix and Sentinel treats it as a single unlabeled hit

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
