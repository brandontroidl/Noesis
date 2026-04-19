// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/dronescan.go — Network drone/botnet detection.

package modules

import (
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

type DroneScan struct {
	pc             *server.PseudoClient
	alertChannel   string
	entropyThresh  float64
	cloneThresh    int
	massJoinThresh int
	massJoinWindow time.Duration
	autoGline      bool
	glineDuration  int
	glineReason    string
	exemptChans    map[string]bool
	mu             sync.Mutex
	hostMap        map[string]int
	realnameMap    map[string]int
	joinTracker    map[string][]time.Time
}

func NewDroneScan() *DroneScan {
	return &DroneScan{exemptChans: make(map[string]bool), hostMap: make(map[string]int), realnameMap: make(map[string]int), joinTracker: make(map[string][]time.Time)}
}

func (d *DroneScan) Name() string { return "dronescan" }

func (d *DroneScan) Init(s *server.Server) error {
	cfg := s.Config().Modules.DroneScan
	if !cfg.Enabled { log.Printf("[%s] disabled", d.Name()); return nil }
	d.alertChannel = cfg.AlertChannel
	d.entropyThresh = cfg.NickEntropyThreshold; if d.entropyThresh <= 0 { d.entropyThresh = 3.5 }
	d.cloneThresh = cfg.CloneThreshold; if d.cloneThresh <= 0 { d.cloneThresh = 5 }
	d.massJoinThresh = cfg.MassJoinThreshold; if d.massJoinThresh <= 0 { d.massJoinThresh = 10 }
	d.massJoinWindow = time.Duration(cfg.MassJoinWindowSecs) * time.Second; if d.massJoinWindow <= 0 { d.massJoinWindow = 30 * time.Second }
	d.autoGline = cfg.AutoGline
	d.glineDuration = cfg.GlineDuration; if d.glineDuration <= 0 { d.glineDuration = 3600 }
	d.glineReason = cfg.GlineReason; if d.glineReason == "" { d.glineReason = "Suspected drone" }
	for _, ch := range cfg.ExemptChannels { d.exemptChans[strings.ToLower(ch)] = true }
	nick := cfg.Nick; if nick == "" { nick = "DroneScan" }
	ident := cfg.Ident; if ident == "" { ident = "drone" }
	gecos := cfg.Gecos; if gecos == "" { gecos = "Drone Detection Service" }
	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, d)
	if err != nil { return fmt.Errorf("introduce %s: %w", nick, err) }
	d.pc = pc
	if d.alertChannel != "" { _ = s.JoinPseudoClient(pc.Numeric, d.alertChannel) }
	log.Printf("[%s] initialized as %s entropy=%.1f clones=%d", d.Name(), nick, d.entropyThresh, d.cloneThresh)
	return nil
}

func (d *DroneScan) RegisterHooks(hm *server.HookManager) {
	hm.Register(server.EventNick, func(s *server.Server, msg *ircv3.P10Message) {
		if d.pc == nil { return }
		u := s.Network().GetUser(msg.Source); if u == nil { return }
		alerts := []string{}
		e := shannonEntropy(u.Nick); if e > d.entropyThresh { alerts = append(alerts, fmt.Sprintf("entropy %.2f", e)) }
		d.mu.Lock()
		d.hostMap[u.Host]++; hc := d.hostMap[u.Host]
		d.realnameMap[u.Gecos]++; rc := d.realnameMap[u.Gecos]
		d.mu.Unlock()
		if hc >= d.cloneThresh { alerts = append(alerts, fmt.Sprintf("%d clones %s", hc, u.Host)) }
		if rc >= d.cloneThresh*2 { alerts = append(alerts, fmt.Sprintf("%d realname '%s'", rc, trunc(u.Gecos, 30))) }
		if len(alerts) > 0 {
			d.alert(s, fmt.Sprintf("\x02[DRONE]\x02 %s (%s@%s): %s", u.Nick, u.Ident, u.Host, strings.Join(alerts, "; ")))
			if d.autoGline && hc >= d.cloneThresh {
				mask := "*@" + u.Host
				_ = s.SendP10(&ircv3.P10Message{Source: s.ServerNumeric(), Command: "GL", Params: []string{"*", "+" + mask, fmt.Sprintf("%d", d.glineDuration), d.glineReason}})
				d.alert(s, fmt.Sprintf("\x02[DRONE]\x02 Glined %s", mask))
			}
		}
	})
	hm.Register(server.EventJoin, func(s *server.Server, msg *ircv3.P10Message) {
		if d.pc == nil || len(msg.Params) < 1 { return }
		now := time.Now()
		d.mu.Lock(); defer d.mu.Unlock()
		for _, ch := range strings.Split(msg.Param(0), ",") {
			cl := strings.ToLower(ch); if d.exemptChans[cl] { continue }
			d.joinTracker[cl] = append(d.joinTracker[cl], now)
			cutoff := now.Add(-d.massJoinWindow); tr := d.joinTracker[cl]; i := 0
			for i < len(tr) && tr[i].Before(cutoff) { i++ }
			d.joinTracker[cl] = tr[i:]
			if len(d.joinTracker[cl]) >= d.massJoinThresh {
				d.alert(s, fmt.Sprintf("\x02[MASSJOIN]\x02 %s: %d joins in %ds", ch, len(d.joinTracker[cl]), int(d.massJoinWindow.Seconds())))
				d.joinTracker[cl] = nil
			}
		}
	})
}

func (d *DroneScan) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if d.pc == nil || (msg.Command != "P" && msg.Command != "PRIVMSG") || len(msg.Params) < 2 { return }
	if !strings.EqualFold(msg.Params[0], d.pc.Nick) && !strings.EqualFold(msg.Params[0], d.pc.Numeric) { return }
	parts := strings.Fields(msg.Params[1]); if len(parts) == 0 { return }
	switch strings.ToUpper(parts[0]) {
	case "HELP":
		for _, l := range []string{"DroneScan — Drone Detection", "  ANALYSE <#chan>  CHECK <nick>  STATUS  EXEMPT ADD|DEL|LIST"} {
			_ = s.SendNotice(d.pc.Numeric, msg.Source, l)
		}
	case "STATUS":
		d.mu.Lock(); h := len(d.hostMap); r := len(d.realnameMap); d.mu.Unlock()
		_ = s.SendNotice(d.pc.Numeric, msg.Source, fmt.Sprintf("Tracking %d hosts, %d realnames", h, r))
	case "ANALYSE":
		if len(parts) < 2 { return }
		ch := s.Network().GetChannel(strings.ToLower(parts[1]))
		if ch == nil { _ = s.SendNotice(d.pc.Numeric, msg.Source, "Channel not found."); return }
		hosts := map[string]int{}; reals := map[string]int{}; var te float64; ct := 0
		for num := range ch.Members {
			u := s.Network().GetUser(num); if u == nil { continue }
			te += shannonEntropy(u.Nick); ct++; hosts[u.Host]++; reals[u.Gecos]++
		}
		_ = s.SendNotice(d.pc.Numeric, msg.Source, fmt.Sprintf("%s: %d members, avg entropy %.2f, %d hosts, %d realnames", parts[1], ct, te/float64(ct+1), len(hosts), len(reals)))
		for h, c := range hosts { if c >= 3 { _ = s.SendNotice(d.pc.Numeric, msg.Source, fmt.Sprintf("  Clone: %s (%d)", h, c)) } }
	case "CHECK":
		if len(parts) < 2 { return }
		u := s.Network().FindUserByNick(parts[1])
		if u == nil { _ = s.SendNotice(d.pc.Numeric, msg.Source, "User not found."); return }
		d.mu.Lock(); hc := d.hostMap[u.Host]; d.mu.Unlock()
		_ = s.SendNotice(d.pc.Numeric, msg.Source, fmt.Sprintf("%s: entropy %.2f, host clones %d", u.Nick, shannonEntropy(u.Nick), hc))
	case "EXEMPT":
		if len(parts) < 2 { return }
		switch strings.ToUpper(parts[1]) {
		case "LIST":
			_ = s.SendNotice(d.pc.Numeric, msg.Source, fmt.Sprintf("Exempt (%d):", len(d.exemptChans)))
			for ch := range d.exemptChans { _ = s.SendNotice(d.pc.Numeric, msg.Source, "  "+ch) }
		case "ADD": if len(parts) >= 3 { d.exemptChans[strings.ToLower(parts[2])] = true }
		case "DEL": if len(parts) >= 3 { delete(d.exemptChans, strings.ToLower(parts[2])) }
		}
	}
}

func (d *DroneScan) alert(s *server.Server, msg string) {
	if d.pc != nil && d.alertChannel != "" { _ = s.SendPrivmsg(d.pc.Numeric, d.alertChannel, msg) }
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 { return 0 }
	freq := map[rune]int{}; for _, c := range s { freq[c]++ }
	e := 0.0; l := float64(len(s))
	for _, c := range freq { p := float64(c) / l; if p > 0 { e -= p * math.Log2(p) } }
	return e
}

func trunc(s string, n int) string { if len(s) <= n { return s }; return s[:n] + "..." }

func (d *DroneScan) Shutdown() { log.Printf("[%s] shutdown", d.Name()) }
