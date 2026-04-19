// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/statserv_html.go — HTML templates for StatServ dashboard.
// Chanstat.net / NeoStats-style network statistics pages.

package modules

import (
	"html/template"
	"strings"
)

var funcMap = template.FuncMap{
	"divf":      func(a, b int64) float64 { if b == 0 { return 0 }; return float64(a) / float64(b) * 100 },
	"stripHash": func(s string) string { return strings.TrimLeft(s, "#&+!") },
	"pct":       func(a, total int64) float64 { if total == 0 { return 0 }; return float64(a) / float64(total) * 100 },
	"sub":       func(a, b int) int { return a - b },
}

// ── CSS ──────────────────────────────────────────────────────────────

const cssTheme = `
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0a0e17;color:#b8c4d4;line-height:1.6;min-height:100vh}
a{color:#4da6ff;text-decoration:none}a:hover{text-decoration:underline;color:#7ec4ff}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
/* Header */
.hdr{background:linear-gradient(135deg,#0f1923 0%,#162231 100%);border-bottom:2px solid #1e3a5f;padding:20px 0;margin-bottom:24px}
.hdr .wrap{display:flex;justify-content:space-between;align-items:center}
.hdr h1{color:#4da6ff;font-size:1.6em;font-weight:700}
.hdr h1 span{color:#8ba4c4;font-weight:400;font-size:.7em}
.hdr nav a{color:#8ba4c4;margin-left:20px;font-size:.9em}
.hdr nav a:hover{color:#4da6ff}
/* Cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:#111b2a;border:1px solid #1e3050;border-radius:10px;padding:18px;text-align:center}
.card .val{font-size:2em;font-weight:800;color:#4da6ff;line-height:1.2}
.card .lbl{font-size:.75em;color:#6b829e;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
/* Tables */
.panel{background:#111b2a;border:1px solid #1e3050;border-radius:10px;overflow:hidden;margin-bottom:24px}
.panel-title{background:#0f1923;padding:12px 18px;font-weight:700;color:#4da6ff;font-size:.95em;border-bottom:1px solid #1e3050}
table{width:100%;border-collapse:collapse}
th{background:#0d1520;color:#6b829e;text-align:left;padding:10px 16px;font-weight:600;font-size:.8em;text-transform:uppercase;letter-spacing:.5px}
td{padding:9px 16px;border-top:1px solid #152235;font-size:.9em}
tr:hover td{background:#141f30}
.n{text-align:right;font-variant-numeric:tabular-nums;font-family:'Consolas','Monaco',monospace}
.q{color:#5a7a9e;font-style:italic;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.85em}
.rank{color:#3a5a7e;font-weight:700;width:30px}
/* Bar chart */
.chart{background:#111b2a;border:1px solid #1e3050;border-radius:10px;padding:20px;margin-bottom:24px}
.chart-title{font-weight:700;color:#4da6ff;font-size:.95em;margin-bottom:16px}
.bars{display:flex;align-items:flex-end;gap:3px;height:140px;padding-bottom:24px;position:relative}
.bar{background:linear-gradient(180deg,#4da6ff 0%,#1e5a9e 100%);border-radius:3px 3px 0 0;flex:1;min-height:2px;position:relative;transition:background .2s}
.bar:hover{background:linear-gradient(180deg,#7ec4ff 0%,#3a7ec4 100%)}
.bar-lbl{position:absolute;bottom:-20px;left:50%;transform:translateX(-50%);font-size:.6em;color:#4a6a8e}
.bar-val{position:absolute;top:-18px;left:50%;transform:translateX(-50%);font-size:.55em;color:#6b829e;white-space:nowrap}
/* Daily chart */
.daily-bars{display:flex;align-items:flex-end;gap:2px;height:80px;padding-bottom:20px}
.daily-bar{background:linear-gradient(180deg,#2ecc71 0%,#1a7a42 100%);border-radius:2px 2px 0 0;flex:1;min-height:1px}
.daily-bar:hover{background:#3ddf80}
/* Topic box */
.topic{background:#0f1923;border-left:3px solid #4da6ff;padding:14px 18px;margin-bottom:24px;border-radius:0 8px 8px 0;color:#8ba4c4;word-wrap:break-word}
/* Word cloud */
.words{display:flex;flex-wrap:wrap;gap:8px;padding:16px}
.word{background:#152235;border:1px solid #1e3a5f;border-radius:6px;padding:4px 12px;font-size:.85em;color:#8ba4c4}
.word .cnt{color:#4a6a8e;font-size:.8em}
/* Footer */
.ft{text-align:center;padding:24px;color:#3a5a7e;font-size:.75em;border-top:1px solid #152235;margin-top:24px}
/* Server list */
.srv-online{color:#2ecc71;font-weight:700}
.srv-name{font-weight:600}
/* Graph placeholder */
.graph-container{background:#111b2a;border:1px solid #1e3050;border-radius:10px;padding:20px;margin-bottom:24px;min-height:300px}
.graph-container svg{width:100%;height:auto}
/* Topic history */
.topic-hist{font-size:.85em}
.topic-hist .setter{color:#4da6ff;font-weight:600}
.topic-hist .when{color:#4a6a8e;font-size:.8em}
/* Breadcrumb */
.bc{color:#5a7a9e;font-size:.9em;margin-bottom:16px}
.bc a{color:#4da6ff}
/* Channel list item */
.ch-users{background:#1e3a5f;color:#4da6ff;border-radius:12px;padding:2px 10px;font-size:.8em;font-weight:700}
</style>
`

// ── Index Page ───────────────────────────────────────────────────────

var tplIndex = template.Must(template.New("index").Funcs(funcMap).Parse(`<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Net}} — Network Statistics</title>` + cssTheme + `</head><body>
<div class="hdr"><div class="wrap">
<h1>{{.Net}} <span>Network Statistics</span></h1>
<nav><a href="/">Channels</a><a href="/network">Network</a></nav>
</div></div>
<div class="wrap">

<div class="cards">
<div class="card"><div class="val">{{.NetUsers}}</div><div class="lbl">Users Online</div></div>
<div class="card"><div class="val">{{.NetChannels}}</div><div class="lbl">Channels</div></div>
<div class="card"><div class="val">{{.NetServers}}</div><div class="lbl">Servers</div></div>
<div class="card"><div class="val">{{.TrackedChannels}}</div><div class="lbl">Tracked</div></div>
<div class="card"><div class="val">{{.PeakUsers}}</div><div class="lbl">Peak Users</div></div>
</div>

<div class="panel">
<div class="panel-title">Tracked Channels</div>
<table>
<thead><tr><th>Channel</th><th class="n">Users</th><th class="n">Lines</th><th class="n">Peak</th><th>Topic</th></tr></thead>
<tbody>
{{range .Chs}}<tr>
<td><a href="/channel/{{stripHash .Name}}">{{.Name}}</a></td>
<td class="n"><span class="ch-users">{{.Users}}</span></td>
<td class="n">{{.Lines}}</td>
<td class="n">{{.Peak}}</td>
<td class="q">{{.Topic}}</td>
</tr>{{end}}
</tbody>
</table>
</div>

<div class="ft">{{.T}} — StatServ / {{.Net}} — Powered by Acid 1.9.0</div>
</div></body></html>`))

// ── Channel Detail Page ──────────────────────────────────────────────

var tplChan = template.Must(template.New("channel").Funcs(funcMap).Parse(`<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Ch}} — {{.Net}} Statistics</title>` + cssTheme + `</head><body>
<div class="hdr"><div class="wrap">
<h1>{{.Net}} <span>Network Statistics</span></h1>
<nav><a href="/">Channels</a><a href="/network">Network</a></nav>
</div></div>
<div class="wrap">

<p class="bc"><a href="/">Home</a> → {{.Ch}}</p>

{{if .Topic}}<div class="topic">{{.Topic}}</div>{{end}}

<div class="cards">
<div class="card"><div class="val">{{.CU}}</div><div class="lbl">Online Now</div></div>
<div class="card"><div class="val">{{.Lines}}</div><div class="lbl">Total Lines</div></div>
<div class="card"><div class="val">{{.UU}}</div><div class="lbl">Unique Users</div></div>
<div class="card"><div class="val">{{.Peak}}</div><div class="lbl">Peak Users</div></div>
<div class="card"><div class="val">{{.Joins}}</div><div class="lbl">Joins</div></div>
<div class="card"><div class="val">{{.Kicks}}</div><div class="lbl">Kicks</div></div>
</div>

<div class="chart">
<div class="chart-title">Activity by Hour (UTC)</div>
<div class="bars">
{{range .Hrs}}<div class="bar" style="height:{{if $.MaxH}}{{printf "%.0f" (divf .L $.MaxH)}}%{{else}}2%{{end}}">
<span class="bar-val">{{.L}}</span><span class="bar-lbl">{{printf "%02d" .H}}</span>
</div>{{end}}
</div>
</div>

{{if .DailyData}}
<div class="chart">
<div class="chart-title">Daily Activity (Last 30 Days)</div>
<div class="daily-bars">
{{range .DailyData}}<div class="daily-bar" style="height:{{if $.MaxD}}{{printf "%.0f" (divf .L $.MaxD)}}%{{else}}1%{{end}}" title="{{.D}}: {{.L}} lines"></div>{{end}}
</div>
</div>
{{end}}

<div class="panel">
<div class="panel-title">Top Talkers</div>
<table>
<thead><tr><th class="rank">#</th><th>Nick</th><th class="n">Lines</th><th class="n">Words</th><th class="n">Actions</th><th>Random Quote</th></tr></thead>
<tbody>
{{range .Tks}}<tr>
<td class="rank">{{.R}}</td><td>{{.N}}</td><td class="n">{{.L}}</td><td class="n">{{.W}}</td><td class="n">{{.A}}</td><td class="q">{{.Q}}</td>
</tr>{{end}}
</tbody>
</table>
</div>

{{if .Wds}}
<div class="panel">
<div class="panel-title">Most Used Words</div>
<div class="words">
{{range .Wds}}<span class="word">{{.W}} <span class="cnt">×{{.C}}</span></span>{{end}}
</div>
</div>
{{end}}

{{if .Topics}}
<div class="panel">
<div class="panel-title">Topic History</div>
<table class="topic-hist">
<thead><tr><th>Set By</th><th>When</th><th>Topic</th></tr></thead>
<tbody>
{{range .Topics}}<tr>
<td class="setter">{{.By}}</td><td class="when">{{.At}}</td><td class="q">{{.T}}</td>
</tr>{{end}}
</tbody>
</table>
</div>
{{end}}

<div class="ft">Tracking since {{.Since}} — {{.T}} — StatServ / {{.Net}}</div>
</div></body></html>`))

// ── Network Page ─────────────────────────────────────────────────────

var tplNetwork = template.Must(template.New("network").Funcs(funcMap).Parse(`<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Net}} — Network Overview</title>` + cssTheme + `</head><body>
<div class="hdr"><div class="wrap">
<h1>{{.Net}} <span>Network Statistics</span></h1>
<nav><a href="/">Channels</a><a href="/network">Network</a></nav>
</div></div>
<div class="wrap">

<div class="cards">
<div class="card"><div class="val">{{.Users}}</div><div class="lbl">Users</div></div>
<div class="card"><div class="val">{{.Channels}}</div><div class="lbl">Channels</div></div>
<div class="card"><div class="val">{{.Servers}}</div><div class="lbl">Servers</div></div>
<div class="card"><div class="val">{{.Opers}}</div><div class="lbl">Opers</div></div>
<div class="card"><div class="val">{{.PeakUsers}}</div><div class="lbl">Peak Users</div></div>
<div class="card"><div class="val">{{.PeakChannels}}</div><div class="lbl">Peak Channels</div></div>
</div>

<div class="panel">
<div class="panel-title">Server List</div>
<table>
<thead><tr><th>Server</th><th>Numeric</th><th>Description</th><th class="n">Users</th><th>Uptime</th></tr></thead>
<tbody>
{{range .Srvs}}<tr>
<td class="srv-name">{{.Name}}</td>
<td>{{.Numeric}}</td>
<td>{{.Desc}}</td>
<td class="n"><span class="srv-online">{{.Users}}</span></td>
<td>{{.Uptime}}</td>
</tr>{{end}}
</tbody>
</table>
</div>

<div class="ft">{{.T}} — StatServ / {{.Net}} — Powered by Acid 1.9.0</div>
</div></body></html>`))
