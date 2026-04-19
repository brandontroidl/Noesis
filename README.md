# Noesis

**Version 1.0.0** — P10 IRC services framework for Cathexis IRCd.

From the Greek νόησις — "thought / perception / intellect." Noesis is the framework the network uses to *think* about itself: user state, channel policy, fun/utility bots, operator tiers, abuse scoring.

## What Noesis is

Noesis is both a **runnable services daemon** and a **Go library** for building your own. It links to Cathexis over P10 with HMAC-SHA256 authentication, handles the full IRCv3 message-tag surface (time, msgid, account, batch, labeled-response, bot-mode), and ships with the Rizon-acid-lineage service bots out of the box:

| Category | Modules |
|---|---|
| Administration | RootServ, OperServ, StatServ |
| Abuse detection | DroneScan, Sentinel (with Cerberus integration) |
| Fun & utility (Rizon pattern) | FunServ (broker), Internets, Trivia, Quotes, LimitServ, Weather, GameServ, Xmas |
| Channel management | TrapBot, Vizon |
| Network directory | ListBots, Registration |
| Integration | CTCP |

The abuse-monitoring / webhook / log-mining layer that used to live alongside these (moo + mod_* modules) has been split out into a separate project, **Aegis**, which consumes Noesis as a library.

## Build & run

```bash
cd ~/Noesis
go build -ldflags="-s -w" -o noesis .
./noesis -config noesis.toml
```

Requires Go 1.22+ and (behind a proxy allowlist) `GOPROXY=direct GOSUMDB=off` to fetch `github.com/BurntSushi/toml` and `github.com/mattn/go-sqlite3`.

## Using Noesis as a framework

Write your own services daemon by importing `github.com/brandontroidl/noesis/server`:

```go
import (
    "github.com/brandontroidl/noesis/config"
    "github.com/brandontroidl/noesis/server"
)

cfg, _ := config.Load("my.toml")
srv, _ := server.New(cfg)
srv.RegisterModule(myModule)      // implements the server.Module interface
srv.RunWithReconnect()
```

See `../Aegis/main.go` for the canonical example. Aegis registers nine moo-lineage modules on a Noesis server without touching Noesis's tree.

## Lineage

Noesis is a direct descendant of Brandon's `acid` services tree through 1.9.0 (itself a Go port of Rizon's Java/Python `acid`). The rename reflects the clean separation from Aegis: `acid` was one project doing two jobs; Noesis is the framework/bot-host half.

## Related projects

- **Cathexis** — the IRCd (P10 / ircu lineage)
- **Synaxis** — conventional services (NickServ/ChanServ/HostServ/etc., x3 lineage)
- **Aegis** — abuse detection + network monitoring (consumer of Noesis)
- **Lexis** — IRCv3 webchat (The Lounge fork)
- **Cerberus** — DNSBL server (self-hosted reputation)
