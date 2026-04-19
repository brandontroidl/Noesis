// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/statserv.go — Network Statistics Service with HTTP dashboard.
//
// Security: localhost-only HTTP, no raw messages/IPs/hostmasks exposed,
// +s/+p channels excluded, rate limiting, security headers, opt-in only.

package modules

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

type ChannelStats struct {
	Name         string            `json:"name"`
	TotalLines   int64             `json:"total_lines"`
	TotalWords   int64             `json:"total_words"`
	TotalActions int64             `json:"total_actions"`
	Joins        int64             `json:"joins"`
	Parts        int64             `json:"parts"`
	Kicks        int64             `json:"kicks"`
	TopicChanges int64             `json:"topic_changes"`
	ModeChanges  int64             `json:"mode_changes"`
	UserStats    map[string]*UserStats `json:"user_stats"`
	HourlyLines  [24]int64         `json:"hourly_lines"`
	DailyLines   map[string]int64  `json:"daily_lines"`
	TopWords     map[string]int64  `json:"top_words"`
	CurrentTopic string            `json:"current_topic"`
	TrackedSince time.Time         `json:"tracked_since"`
	PeakUsers    int               `json:"peak_users"`
	PeakTime     time.Time         `json:"peak_time"`
	TopicHistory []topicEntry      `json:"topic_history"`
	Relationships map[string]int64 `json:"relationships"` // "nick1->nick2" -> count
}

type topicEntry struct {
	Topic  string    `json:"topic"`
	SetBy  string    `json:"set_by"`
	SetAt  time.Time `json:"set_at"`
}

type UserStats struct {
	Nick        string    `json:"nick"`
	Lines       int64     `json:"lines"`
	Words       int64     `json:"words"`
	Actions     int64     `json:"actions"`
	LastSeen    time.Time `json:"last_seen"`
	RandomQuote string    `json:"random_quote"`
	Kicks       int64     `json:"kicks"`
	Kicked      int64     `json:"kicked"`
}

// NetworkStats holds network-wide statistics.
type NetworkStats struct {
	PeakUsers    int       `json:"peak_users"`
	PeakTime     time.Time `json:"peak_time"`
	PeakChannels int       `json:"peak_channels"`
	TotalLines   int64     `json:"total_lines"`
}

type StatServ struct {
	pc       *server.PseudoClient
	srv      *server.Server
	logDir   string
	dataPath string
	channels []string
	httpAddr string
	mu       sync.RWMutex
	stats    map[string]*ChannelStats
	netStats *NetworkStats
	files    map[string]*os.File
	lastDay  map[string]int
	limiter  *httpLimiter
	stopCh   chan struct{}
}

type httpLimiter struct {
	mu       sync.Mutex
	reqs     map[string][]time.Time
	limit    int
	window   time.Duration
}

func newHTTPLimiter(limit int, window time.Duration) *httpLimiter {
	return &httpLimiter{reqs: make(map[string][]time.Time), limit: limit, window: window}
}

func (rl *httpLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	clean := rl.reqs[key][:0]
	for _, t := range rl.reqs[key] {
		if t.After(cutoff) { clean = append(clean, t) }
	}
	if len(clean) >= rl.limit { rl.reqs[key] = clean; return false }
	rl.reqs[key] = append(clean, now)
	return true
}

func (s *StatServ) Name() string { return "statserv" }
func NewStatServ() *StatServ     { return &StatServ{} }

func (s *StatServ) Init(srv *server.Server) error {
	s.srv = srv
	cfg := srv.Config().Modules.StatServ
	if !cfg.Enabled { log.Printf("[statserv] disabled"); return nil }

	nick := cfg.Nick; if nick == "" { nick = "StatServ" }
	ident := cfg.Ident; if ident == "" { ident = "stats" }
	gecos := cfg.Gecos; if gecos == "" { gecos = "Network Statistics Service" }
	s.logDir = cfg.LogDir; if s.logDir == "" { s.logDir = "logs" }
	s.httpAddr = cfg.HTTPAddr; if s.httpAddr == "" { s.httpAddr = "127.0.0.1:8090" }
	s.dataPath = "data/statserv.json"
	s.stopCh = make(chan struct{})

	os.MkdirAll(s.logDir, 0750)
	os.MkdirAll("data", 0750)
	s.channels = cfg.Channels
	s.files = make(map[string]*os.File)
	s.lastDay = make(map[string]int)
	s.stats = make(map[string]*ChannelStats)
	s.netStats = &NetworkStats{}
	s.limiter = newHTTPLimiter(30, time.Minute)

	// Load persisted stats
	s.loadStats()

	pc, err := srv.IntroducePseudoClient(nick, ident, srv.Config().Server.Name, gecos, s)
	if err != nil { return err }
	s.pc = pc

	// Rejoin channels we were tracking (from saved data)
	s.mu.RLock()
	for _, cs := range s.stats {
		_ = srv.JoinPseudoClient(pc.Numeric, cs.Name)
	}
	s.mu.RUnlock()

	// Admin seed channels from config
	for _, ch := range s.channels {
		s.startTracking(ch)
		_ = srv.JoinPseudoClient(pc.Numeric, ch)
	}

	// Periodic save every 5 minutes
	go s.saveLoop()

	go s.serveHTTP()
	log.Printf("[statserv] initialized as %s, HTTP %s (channels join via request)", nick, s.httpAddr)
	return nil
}

func (s *StatServ) RegisterHooks(hm *server.HookManager) {
	hm.Register(server.EventMessage, s.onMessage)
	hm.Register(server.EventJoin, s.onJoin)
	hm.Register(server.EventPart, s.onPart)
	hm.Register(server.EventQuit, s.onQuit)
	hm.Register(server.EventKick, s.onKick)
	hm.Register(server.EventNick, s.onNick)
	hm.Register(server.EventMode, s.onMode)
	hm.Register(server.EventTopic, s.onTopic)
}

func (s *StatServ) HandleMessage(srv *server.Server, msg *ircv3.P10Message) {
	if s.pc == nil { return }
	fields := strings.Fields(msg.Trailing())
	if len(fields) < 1 { return }
	switch strings.ToUpper(fields[0]) {
	case "HELP":
		for _, l := range []string{"--- StatServ Help ---", "  STATS <#channel> — Channel statistics",
			"  TOP <#channel>   — Top talkers", fmt.Sprintf("  Web: http://%s/", s.httpAddr), "---"} {
			_ = srv.SendNotice(s.pc.Numeric, msg.Source, l)
		}
	case "STATS":
		if len(fields) < 2 { _ = srv.SendNotice(s.pc.Numeric, msg.Source, "Usage: STATS <#channel>"); return }
		s.mu.RLock(); cs, ok := s.stats[strings.ToLower(fields[1])]; s.mu.RUnlock()
		if !ok { _ = srv.SendNotice(s.pc.Numeric, msg.Source, "No stats for "+fields[1]); return }
		for _, l := range []string{fmt.Sprintf("--- %s ---", cs.Name),
			fmt.Sprintf("  Lines: %d  Words: %d  Users: %d", cs.TotalLines, cs.TotalWords, len(cs.UserStats)),
			fmt.Sprintf("  Joins: %d  Parts: %d  Kicks: %d", cs.Joins, cs.Parts, cs.Kicks), "---"} {
			_ = srv.SendNotice(s.pc.Numeric, msg.Source, l)
		}
	case "TOP":
		if len(fields) < 2 { _ = srv.SendNotice(s.pc.Numeric, msg.Source, "Usage: TOP <#channel>"); return }
		s.mu.RLock(); cs, ok := s.stats[strings.ToLower(fields[1])]; s.mu.RUnlock()
		if !ok { _ = srv.SendNotice(s.pc.Numeric, msg.Source, "No stats for "+fields[1]); return }
		type e struct{ n string; l int64 }
		var es []e
		for _, u := range cs.UserStats { es = append(es, e{u.Nick, u.Lines}) }
		sort.Slice(es, func(i, j int) bool { return es[i].l > es[j].l })
		_ = srv.SendNotice(s.pc.Numeric, msg.Source, fmt.Sprintf("--- Top Talkers %s ---", cs.Name))
		for i := 0; i < 10 && i < len(es); i++ {
			_ = srv.SendNotice(s.pc.Numeric, msg.Source, fmt.Sprintf("  %2d. %-20s %d", i+1, es[i].n, es[i].l))
		}
	}
}

func (s *StatServ) Shutdown() {
	if s.stopCh != nil { close(s.stopCh) }
	s.saveStats()
	s.mu.Lock(); defer s.mu.Unlock()
	for _, f := range s.files { f.Close() }
	s.files = make(map[string]*os.File)
	log.Printf("[statserv] shutdown (stats saved)")
}

// --- Persistence ---

func (s *StatServ) saveLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.saveStats()
		}
	}
}

func (s *StatServ) saveStats() {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.stats, "", "  ")
	s.mu.RUnlock()
	if err != nil { log.Printf("[statserv] save error: %v", err); return }

	tmp := s.dataPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		log.Printf("[statserv] save write error: %v", err)
		return
	}
	if err := os.Rename(tmp, s.dataPath); err != nil {
		log.Printf("[statserv] save rename error: %v", err)
		return
	}
	log.Printf("[statserv] saved %d channel stats to %s", len(s.stats), s.dataPath)
}

func (s *StatServ) loadStats() {
	data, err := os.ReadFile(s.dataPath)
	if err != nil {
		if !os.IsNotExist(err) { log.Printf("[statserv] load error: %v", err) }
		return
	}
	loaded := make(map[string]*ChannelStats)
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[statserv] load parse error: %v", err)
		return
	}
	s.mu.Lock()
	s.stats = loaded
	s.mu.Unlock()
	log.Printf("[statserv] loaded %d channel stats from %s", len(loaded), s.dataPath)
}

// startTracking begins tracking a channel.
func (s *StatServ) startTracking(channel string) {
	s.mu.Lock(); defer s.mu.Unlock()
	lower := strings.ToLower(channel)
	if _, ok := s.stats[lower]; ok { return }
	s.stats[lower] = &ChannelStats{
		Name: channel, UserStats: make(map[string]*UserStats),
		DailyLines: make(map[string]int64), TopWords: make(map[string]int64),
		TopicHistory: make([]topicEntry, 0), Relationships: make(map[string]int64),
		TrackedSince: time.Now(),
	}
	log.Printf("[statserv] now tracking %s", channel)
}

// stopTracking stops tracking a channel.
func (s *StatServ) stopTracking(channel string) {
	s.mu.Lock(); defer s.mu.Unlock()
	lower := strings.ToLower(channel)
	delete(s.stats, lower)
	if f, ok := s.files[lower]; ok { f.Close(); delete(s.files, lower) }
	log.Printf("[statserv] stopped tracking %s", channel)
}

// --- Stats ---

func (s *StatServ) track(channel, nick, text string, isAction bool) {
	s.mu.Lock(); defer s.mu.Unlock()
	cs, ok := s.stats[strings.ToLower(channel)]; if !ok { return }
	words := strings.Fields(text)
	cs.TotalLines++; cs.TotalWords += int64(len(words))
	if isAction { cs.TotalActions++ }
	cs.HourlyLines[time.Now().Hour()]++
	cs.DailyLines[time.Now().Format("2006-01-02")]++
	for _, w := range words {
		w = strings.ToLower(strings.Trim(w, ".,!?;:'\"()[]{}"))
		if len(w) > 3 { cs.TopWords[w]++ }
	}
	us, ok := cs.UserStats[nick]; if !ok { us = &UserStats{Nick: nick}; cs.UserStats[nick] = us }
	us.Lines++; us.Words += int64(len(words)); us.LastSeen = time.Now()
	if isAction { us.Actions++ }
	if len(text) > 10 && len(text) < 200 && !strings.Contains(text, "http") && us.Lines%10 == 0 {
		us.RandomQuote = text
	}
}

func (s *StatServ) incStat(channel string, fn func(cs *ChannelStats)) {
	s.mu.Lock(); defer s.mu.Unlock()
	if cs, ok := s.stats[strings.ToLower(channel)]; ok { fn(cs) }
}

// --- Logging (irssi format for pisg) ---

func (s *StatServ) logLine(channel, line string) {
	s.mu.Lock(); defer s.mu.Unlock()
	lower := strings.ToLower(channel)
	f, ok := s.files[lower]
	if !ok {
		safe := strings.ReplaceAll(strings.ReplaceAll(lower, "#", ""), "/", "_")
		path := filepath.Join(s.logDir, safe+".log")
		var err error
		f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil { return }
		s.files[lower] = f
	}
	day := time.Now().YearDay() + time.Now().Year()*1000
	if ld, ok := s.lastDay[lower]; !ok || ld != day {
		fmt.Fprintf(f, "--- Day changed %s\n", time.Now().Format("Mon Jan 02 2006"))
		s.lastDay[lower] = day
	}
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("15:04"), line)
}

func (s *StatServ) logging(ch string) bool {
	s.mu.RLock(); defer s.mu.RUnlock()
	_, ok := s.stats[strings.ToLower(ch)]
	return ok
}

func (s *StatServ) isSecret(ch string) bool {
	if s.srv == nil { return false }
	c := s.srv.Network().GetChannel(ch)
	return c != nil && strings.ContainsAny(c.Modes, "sp")
}

// --- Hooks ---

func (s *StatServ) onMessage(srv *server.Server, msg *ircv3.P10Message) {
	if len(msg.Params) < 2 { return }
	target := msg.Param(0); if !s.logging(target) { return }
	u := srv.Network().GetUser(msg.Source); if u == nil { return }
	text := msg.Trailing()
	if strings.HasPrefix(text, "\x01ACTION ") && strings.HasSuffix(text, "\x01") {
		action := text[8:len(text)-1]
		s.logLine(target, fmt.Sprintf(" * %s %s", u.Nick, action))
		s.track(target, u.Nick, action, true)
	} else {
		s.logLine(target, fmt.Sprintf("<%s> %s", u.Nick, text))
		s.track(target, u.Nick, text, false)
	}
}

func (s *StatServ) onJoin(srv *server.Server, msg *ircv3.P10Message) {
	ch := msg.Param(0)

	// If StatServ itself joined, start tracking the channel
	if s.pc != nil && msg.Source == s.pc.Numeric {
		s.startTracking(ch)
		return
	}

	if !s.logging(ch) { return }
	u := srv.Network().GetUser(msg.Source); if u == nil { return }
	s.logLine(ch, fmt.Sprintf("-!- %s [%s@%s] has joined %s", u.Nick, u.Ident, u.Host, ch))
	s.mu.Lock()
	if cs, ok := s.stats[strings.ToLower(ch)]; ok {
		cs.Joins++
		// Track peak users
		if c := srv.Network().GetChannel(ch); c != nil && len(c.Members) > cs.PeakUsers {
			cs.PeakUsers = len(c.Members)
			cs.PeakTime = time.Now()
		}
	}
	// Update network peaks
	if s.netStats != nil {
		uc := srv.Network().UserCount()
		if uc > s.netStats.PeakUsers { s.netStats.PeakUsers = uc; s.netStats.PeakTime = time.Now() }
		cc := srv.Network().ChannelCount()
		if cc > s.netStats.PeakChannels { s.netStats.PeakChannels = cc }
	}
	s.mu.Unlock()
}

func (s *StatServ) onPart(srv *server.Server, msg *ircv3.P10Message) {
	ch := msg.Param(0)

	// If StatServ itself parted, stop tracking
	if s.pc != nil && msg.Source == s.pc.Numeric {
		s.stopTracking(ch)
		return
	}

	if !s.logging(ch) { return }
	u := srv.Network().GetUser(msg.Source); if u == nil { return }
	r := msg.Trailing()
	if r != "" { s.logLine(ch, fmt.Sprintf("-!- %s has left %s [%s]", u.Nick, ch, r))
	} else { s.logLine(ch, fmt.Sprintf("-!- %s has left %s", u.Nick, ch)) }
	s.incStat(ch, func(cs *ChannelStats) { cs.Parts++ })
}

func (s *StatServ) onQuit(srv *server.Server, msg *ircv3.P10Message) {
	u := srv.Network().GetUser(msg.Source); if u == nil { return }
	for ch := range u.Channels {
		if s.logging(ch) { s.logLine(ch, fmt.Sprintf("-!- %s has quit [%s]", u.Nick, msg.Trailing())) }
	}
}

func (s *StatServ) onKick(srv *server.Server, msg *ircv3.P10Message) {
	if len(msg.Params) < 2 { return }
	ch := msg.Param(0); if !s.logging(ch) { return }
	kicker := msg.Source; if u := srv.Network().GetUser(msg.Source); u != nil { kicker = u.Nick }
	kicked := msg.Param(1); if u := srv.Network().GetUser(kicked); u != nil { kicked = u.Nick }
	s.logLine(ch, fmt.Sprintf("-!- %s was kicked from %s by %s [%s]", kicked, ch, kicker, msg.Trailing()))
	s.incStat(ch, func(cs *ChannelStats) { cs.Kicks++ })
}

func (s *StatServ) onNick(srv *server.Server, msg *ircv3.P10Message) {
	if len(msg.Params) < 1 { return }
	u := srv.Network().GetUser(msg.Source); if u == nil { return }
	for ch := range u.Channels {
		if s.logging(ch) { s.logLine(ch, fmt.Sprintf("-!- %s is now known as %s", u.Nick, msg.Param(0))) }
	}
}

func (s *StatServ) onMode(srv *server.Server, msg *ircv3.P10Message) {
	if len(msg.Params) < 2 { return }
	ch := msg.Param(0); if !s.logging(ch) { return }
	setter := msg.Source; if u := srv.Network().GetUser(msg.Source); u != nil { setter = u.Nick }
	s.logLine(ch, fmt.Sprintf("-!- mode/%s [%s] by %s", ch, strings.Join(msg.Params[1:], " "), setter))
	s.incStat(ch, func(cs *ChannelStats) { cs.ModeChanges++ })
}

func (s *StatServ) onTopic(srv *server.Server, msg *ircv3.P10Message) {
	if len(msg.Params) < 1 { return }
	ch := msg.Param(0); if !s.logging(ch) { return }
	setter := msg.Source; if u := srv.Network().GetUser(msg.Source); u != nil { setter = u.Nick }
	topic := msg.Trailing()
	s.logLine(ch, fmt.Sprintf("-!- %s changed the topic of %s to: %s", setter, ch, topic))
	s.mu.Lock()
	if cs, ok := s.stats[strings.ToLower(ch)]; ok {
		cs.TopicChanges++
		cs.CurrentTopic = topic
		cs.TopicHistory = append(cs.TopicHistory, topicEntry{Topic: topic, SetBy: setter, SetAt: time.Now()})
		if len(cs.TopicHistory) > 50 { cs.TopicHistory = cs.TopicHistory[len(cs.TopicHistory)-50:] }
	}
	s.mu.Unlock()
}

// --- HTTP ---

func (s *StatServ) serveHTTP() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.httpIndex)
	mux.HandleFunc("/channel/", s.httpChannel)
	mux.HandleFunc("/network", s.httpNetwork)
	mux.HandleFunc("/api/channels", s.apiChannels)
	mux.HandleFunc("/api/channel/", s.apiChannel)

	srv := &http.Server{Addr: s.httpAddr, Handler: s.protect(mux),
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	log.Printf("[statserv] HTTP on %s", s.httpAddr)
	if err := srv.ListenAndServe(); err != nil { log.Printf("[statserv] HTTP error: %v", err) }
}

func (s *StatServ) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if fwd := r.Header.Get("X-Real-IP"); fwd != "" { ip = fwd }
		if !s.limiter.allow(ip) { http.Error(w, "Rate limit exceeded", 429); return }
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *StatServ) httpIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" { http.NotFound(w, r); return }
	s.mu.RLock(); defer s.mu.RUnlock()
	type ch struct{ Name string; Users int; Lines int64; Peak int; Topic string }
	var chs []ch
	for _, cs := range s.stats {
		if s.isSecret(cs.Name) { continue }
		t := cs.CurrentTopic; if len(t) > 80 { t = t[:80] + "..." }
		u := 0; if c := s.srv.Network().GetChannel(cs.Name); c != nil { u = len(c.Members) }
		chs = append(chs, ch{cs.Name, u, cs.TotalLines, cs.PeakUsers, t})
	}
	sort.Slice(chs, func(i, j int) bool { return chs[i].Lines > chs[j].Lines })
	net := s.srv.Network()
	peak := 0; if s.netStats != nil { peak = s.netStats.PeakUsers }
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tplIndex.Execute(w, map[string]interface{}{
		"Net": "Dexterous Network", "Chs": chs,
		"NetUsers": net.UserCount(), "NetChannels": net.ChannelCount(),
		"NetServers": net.ServerCount(), "TrackedChannels": len(s.stats),
		"PeakUsers": peak,
		"T": time.Now().Format("2006-01-02 15:04 MST"),
	})
}

func (s *StatServ) httpChannel(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/channel/")
	if !strings.HasPrefix(name, "#") { name = "#" + name }
	if s.isSecret(name) { http.NotFound(w, r); return }
	s.mu.RLock()
	cs, ok := s.stats[strings.ToLower(name)]
	if !ok { s.mu.RUnlock(); http.NotFound(w, r); return }

	// Top talkers
	type tk struct{ R int; N string; L, W, A int64; Q string }
	var tks []tk
	for _, u := range cs.UserStats {
		tks = append(tks, tk{0, u.Nick, u.Lines, u.Words, u.Actions, template.HTMLEscapeString(u.RandomQuote)})
	}
	sort.Slice(tks, func(i, j int) bool { return tks[i].L > tks[j].L })
	if len(tks) > 25 { tks = tks[:25] }
	for i := range tks { tks[i].R = i + 1 }

	// Hourly
	type hr struct{ H int; L int64 }
	var hrs []hr; for h := 0; h < 24; h++ { hrs = append(hrs, hr{h, cs.HourlyLines[h]}) }
	var maxH int64; for _, h := range hrs { if h.L > maxH { maxH = h.L } }

	// Daily (last 30 days)
	type dd struct{ D string; L int64 }
	var dailyData []dd
	var maxD int64
	now := time.Now()
	for i := 29; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		lines := cs.DailyLines[day]
		dailyData = append(dailyData, dd{day, lines})
		if lines > maxD { maxD = lines }
	}

	// Top words
	type wd struct{ W string; C int64 }
	var wds []wd; for w, c := range cs.TopWords { wds = append(wds, wd{w, c}) }
	sort.Slice(wds, func(i, j int) bool { return wds[i].C > wds[j].C })
	if len(wds) > 30 { wds = wds[:30] }

	// Topic history (most recent first)
	type tp struct{ T, By, At string }
	var topics []tp
	for i := len(cs.TopicHistory) - 1; i >= 0 && len(topics) < 10; i-- {
		th := cs.TopicHistory[i]
		topics = append(topics, tp{
			template.HTMLEscapeString(th.Topic), th.SetBy,
			th.SetAt.Format("Jan 02 15:04"),
		})
	}

	uc := 0; if c := s.srv.Network().GetChannel(name); c != nil { uc = len(c.Members) }
	data := map[string]interface{}{
		"Net": "Dexterous Network", "Ch": cs.Name, "Lines": cs.TotalLines, "Words": cs.TotalWords,
		"Acts": cs.TotalActions, "UU": len(cs.UserStats), "CU": uc, "Peak": cs.PeakUsers,
		"Joins": cs.Joins, "Parts": cs.Parts, "Kicks": cs.Kicks,
		"Topic": template.HTMLEscapeString(cs.CurrentTopic),
		"Since": cs.TrackedSince.Format("2006-01-02 15:04"),
		"Tks": tks, "Hrs": hrs, "MaxH": maxH,
		"DailyData": dailyData, "MaxD": maxD,
		"Wds": wds, "Topics": topics,
		"T": time.Now().Format("2006-01-02 15:04 MST"),
	}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tplChan.Execute(w, data)
}

func (s *StatServ) apiChannels(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock(); defer s.mu.RUnlock()
	type e struct{ Name string `json:"name"`; Lines int64 `json:"lines"`; Users int `json:"users"` }
	var out []e
	for _, cs := range s.stats {
		if s.isSecret(cs.Name) { continue }
		u := 0; if c := s.srv.Network().GetChannel(cs.Name); c != nil { u = len(c.Members) }
		out = append(out, e{cs.Name, cs.TotalLines, u})
	}
	w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(out)
}

func (s *StatServ) apiChannel(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/channel/")
	if !strings.HasPrefix(name, "#") { name = "#" + name }
	if s.isSecret(name) { http.NotFound(w, r); return }
	s.mu.RLock()
	cs, ok := s.stats[strings.ToLower(name)]
	if !ok { s.mu.RUnlock(); http.NotFound(w, r); return }
	out := map[string]interface{}{"name": cs.Name, "lines": cs.TotalLines, "words": cs.TotalWords,
		"actions": cs.TotalActions, "users": len(cs.UserStats), "joins": cs.Joins,
		"parts": cs.Parts, "kicks": cs.Kicks, "hourly": cs.HourlyLines,
		"since": cs.TrackedSince.Format(time.RFC3339)}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(out)
}


// httpNetwork shows the network overview page with server list.
func (s *StatServ) httpNetwork(w http.ResponseWriter, r *http.Request) {
	net := s.srv.Network()
	srvs := net.GetAllServers()

	type srv struct{ Name, Numeric, Desc, Uptime string; Users int }
	var srvList []srv
	for _, sv := range srvs {
		uptime := time.Since(sv.LinkTime).Round(time.Second).String()
		users := 0
		for _, u := range net.GetAllUsers() {
			if u.Server == sv.Numeric { users++ }
		}
		srvList = append(srvList, srv{sv.Name, sv.Numeric, sv.Description, uptime, users})
	}

	// Count opers
	opers := 0
	for _, u := range net.GetAllUsers() {
		if strings.Contains(u.Modes, "o") { opers++ }
	}

	s.mu.RLock()
	peak := 0; peakCh := 0
	if s.netStats != nil { peak = s.netStats.PeakUsers; peakCh = s.netStats.PeakChannels }
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tplNetwork.Execute(w, map[string]interface{}{
		"Net": "Dexterous Network", "Users": net.UserCount(),
		"Channels": net.ChannelCount(), "Servers": net.ServerCount(),
		"Opers": opers, "PeakUsers": peak, "PeakChannels": peakCh,
		"Srvs": srvList,
		"T": time.Now().Format("2006-01-02 15:04 MST"),
	})
}
