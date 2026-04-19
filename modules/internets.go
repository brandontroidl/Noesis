// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/internets.go — Internets search/utility bot.
//
// Ported from Rizon acid's pyva/internets/. Rizon's Internets bot hosts the
// commands that used to be scattered across Weather, GameServ, and
// FunServ-inline handlers in earlier Brandon acid revisions:
//
//   weather, forecast, register_location, dice, calc,
//   ud (urbandictionary), qdb, fml, steam, lastfm, imdb,
//   twitch, youtube_search, url_shorten, url_expand, ipinfo,
//   bing_translate, google_search, google_image_search,
//   dictionary, internets_help, internets_info, idlerpg
//
// Commands that require external API credentials (Google, Bing, Steam, LastFM,
// Twitch, OpenWeatherMap, etc.) are stubbed with a "not configured" reply
// unless the corresponding api_* config field is populated.

package modules

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

type Internets struct {
	pc  *server.PseudoClient
	cfg InternetsRuntime

	locMu    sync.RWMutex
	userLocs map[string]string // account -> location

	// Russian-roulette per-channel state (migrated from Synaxis BotServ).
	// Chamber value 0 = empty; 1-6 = loaded (first pull). Any subsequent
	// pull while loaded kills the user, matching x3 cmd_roulette behavior.
	rouletteMu       sync.Mutex
	rouletteChambers map[string]int // channel (lowercase) -> chamber

	http *http.Client
}

// InternetsRuntime holds the per-command API keys and feature toggles.
// Loaded from config.Modules.Internets at Init.
type InternetsRuntime struct {
	OpenWeatherKey   string
	GoogleKey        string
	GoogleSearchCX   string
	BingKey          string
	SteamKey         string
	LastFMKey        string
	TwitchClientID   string
	TwitchSecret     string
	YouTubeKey       string
	WolframAppID     string
}

func NewInternets() *Internets {
	return &Internets{
		userLocs:         make(map[string]string),
		rouletteChambers: make(map[string]int),
		http:             &http.Client{Timeout: 10 * time.Second},
	}
}
func (i *Internets) Name() string { return "internets" }

func (i *Internets) Init(s *server.Server) error {
	cfg := s.Config().Modules.Internets
	if !cfg.Enabled {
		log.Printf("[%s] disabled", i.Name())
		return nil
	}
	nick := cfg.Nick
	if nick == "" {
		nick = "Internets"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "internets"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Internet Search and Utility Bot"
	}

	i.cfg = InternetsRuntime{
		OpenWeatherKey: cfg.OpenWeatherKey,
		GoogleKey:      cfg.GoogleKey,
		GoogleSearchCX: cfg.GoogleSearchCX,
		BingKey:        cfg.BingKey,
		SteamKey:       cfg.SteamKey,
		LastFMKey:      cfg.LastFMKey,
		TwitchClientID: cfg.TwitchClientID,
		TwitchSecret:   cfg.TwitchSecret,
		YouTubeKey:     cfg.YouTubeKey,
		WolframAppID:   cfg.WolframAppID,
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, i)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	i.pc = pc
	log.Printf("[%s] initialized as %s", i.Name(), nick)
	return nil
}

func (i *Internets) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if i.pc == nil || (msg.Command != "P" && msg.Command != "PRIVMSG") || len(msg.Params) < 2 {
		return
	}
	tgt := msg.Params[0]
	text := msg.Params[1]

	// Direct PM: handle REQUEST / REMOVE / HELP, and the full command set.
	// Channel: react only to dot-triggered commands (.weather, .dice, etc.).
	isDirect := strings.EqualFold(tgt, i.pc.Nick) || strings.EqualFold(tgt, i.pc.Numeric)
	replyTarget := msg.Source
	var cmdText string

	if isDirect {
		cmdText = strings.TrimSpace(text)
	} else if strings.HasPrefix(tgt, "#") || strings.HasPrefix(tgt, "&") {
		if !strings.HasPrefix(text, ".") {
			return
		}
		cmdText = strings.TrimPrefix(text, ".")
		replyTarget = tgt
	} else {
		return
	}
	parts := strings.Fields(cmdText)
	if len(parts) == 0 {
		return
	}
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "internets_help":
		i.help(s, replyTarget)
	case "info", "internets_info":
		_ = s.SendNotice(i.pc.Numeric, replyTarget, "Internets — Rizon-style search/utility bot. See HELP for commands.")
	case "dice", "d":
		// `.d` is the x3-BotServ-compatible alias; `.dice` is the Rizon form.
		i.dice(s, replyTarget, args)
	case "coin":
		i.coin(s, replyTarget)
	case "8ball":
		i.eightBall(s, replyTarget)
	case "calc":
		i.calc(s, replyTarget, args)
	case "roulette":
		// BotServ-compatible russian-roulette toy (migrated from Synaxis).
		i.roulette(s, replyTarget, msg.Source)
	case "unf":
		i.botservUnf(s, replyTarget, msg.Source)
	case "ping":
		i.botservPing(s, replyTarget, msg.Source)
	case "wut":
		i.botservWut(s, replyTarget, msg.Source)
	case "huggle":
		i.botservHuggle(s, replyTarget, msg.Source)
	case "reply":
		i.botservReply(s, replyTarget, msg.Source, args)
	case "weather":
		i.weather(s, replyTarget, msg.Source, args)
	case "forecast":
		i.forecast(s, replyTarget, msg.Source, args)
	case "register_location", "setloc":
		i.registerLocation(s, replyTarget, msg.Source, args)
	case "ud", "urbandictionary":
		i.urbanDictionary(s, replyTarget, args)
	case "qdb":
		i.qdb(s, replyTarget, args)
	case "fml":
		i.fml(s, replyTarget)
	case "steam":
		i.steam(s, replyTarget, args)
	case "lastfm":
		i.lastfm(s, replyTarget, args)
	case "imdb":
		i.imdb(s, replyTarget, args)
	case "twitch":
		i.twitch(s, replyTarget, args)
	case "youtube", "youtube_search":
		i.youtube(s, replyTarget, args)
	case "ipinfo":
		i.ipinfo(s, replyTarget, args)
	case "url_shorten":
		i.urlShorten(s, replyTarget, args)
	case "url_expand":
		i.urlExpand(s, replyTarget, args)
	case "google", "google_search":
		i.googleSearch(s, replyTarget, args, false)
	case "google_image", "google_image_search":
		i.googleSearch(s, replyTarget, args, true)
	case "dictionary":
		i.dictionary(s, replyTarget, args)
	case "bing_translate":
		i.bingTranslate(s, replyTarget, args)
	default:
		if isDirect {
			_ = s.SendNotice(i.pc.Numeric, replyTarget, "Unknown command. Use HELP.")
		}
	}
}

func (i *Internets) Shutdown() {}

// -----------------------------------------------------------------------
// Command implementations
// -----------------------------------------------------------------------

func (i *Internets) help(s *server.Server, target string) {
	lines := []string{
		"\x02Internets\x02 commands (prefix in-channel with '.'):",
		"  Games:     dice <NdM>, coin, 8ball",
		"  Math:      calc <expr>",
		"  Weather:   weather [location], forecast [location], register_location <loc>",
		"  Lookup:    ud <term>, qdb [id|search], fml, dictionary <word>",
		"  Media:     imdb <title>, youtube <q>, lastfm <user>, twitch <channel>, steam <user>",
		"  URL:       url_shorten <url>, url_expand <url>",
		"  Search:    google <q>, google_image <q>, bing_translate <text>",
		"  Network:   ipinfo <ip>",
	}
	for _, l := range lines {
		_ = s.SendNotice(i.pc.Numeric, target, l)
	}
}

func (i *Internets) dice(s *server.Server, target string, args []string) {
	if len(args) < 1 {
		_ = s.SendNotice(i.pc.Numeric, target, "Usage: dice 2d6")
		return
	}
	p := strings.SplitN(strings.ToLower(args[0]), "d", 2)
	if len(p) != 2 {
		_ = s.SendNotice(i.pc.Numeric, target, "Format: NdM (e.g. 2d6)")
		return
	}
	n, e1 := strconv.Atoi(p[0])
	m, e2 := strconv.Atoi(p[1])
	if e1 != nil || e2 != nil || n < 1 || n > 100 || m < 2 || m > 1000 {
		_ = s.SendNotice(i.pc.Numeric, target, "Invalid dice spec.")
		return
	}
	total := 0
	rolls := make([]string, 0, n)
	for j := 0; j < n; j++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(int64(m)))
		v := int(r.Int64()) + 1
		total += v
		rolls = append(rolls, strconv.Itoa(v))
	}
	_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("%s: [%s] = %d", args[0], strings.Join(rolls, ","), total))
}

func (i *Internets) coin(s *server.Server, target string) {
	r, _ := rand.Int(rand.Reader, big.NewInt(2))
	if r.Int64() == 0 {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "Heads")
	} else {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "Tails")
	}
}

func (i *Internets) eightBall(s *server.Server, target string) {
	resp := []string{
		"Yes.", "No.", "Maybe.", "Absolutely.", "Doubtful.", "Ask again.",
		"It is certain.", "Very doubtful.", "Signs point to yes.",
		"My sources say no.", "Outlook good.", "Cannot predict now.",
	}
	r, _ := rand.Int(rand.Reader, big.NewInt(int64(len(resp))))
	_ = s.SendPrivmsg(i.pc.Numeric, target, resp[r.Int64()])
}

func (i *Internets) calc(s *server.Server, target string, args []string) {
	if len(args) == 0 {
		_ = s.SendNotice(i.pc.Numeric, target, "Usage: calc <expression>")
		return
	}
	expr := strings.Join(args, " ")
	// Security: only allow digits, operators, spaces, parens, dots
	for _, r := range expr {
		if !strings.ContainsRune("0123456789+-*/(). ", r) {
			_ = s.SendNotice(i.pc.Numeric, target, "Invalid characters in expression.")
			return
		}
	}
	result, err := evalSimpleExpr(expr)
	if err != nil {
		_ = s.SendNotice(i.pc.Numeric, target, "Parse error: "+err.Error())
		return
	}
	_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("%s = %s", expr, result))
}

func (i *Internets) weather(s *server.Server, target, source string, args []string) {
	if i.cfg.OpenWeatherKey == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "Weather is not configured on this network.")
		return
	}
	location := strings.Join(args, " ")
	if location == "" {
		location = i.lookupRegisteredLocation(source)
	}
	if location == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "Usage: weather <location>  (or register_location first)")
		return
	}
	u := fmt.Sprintf("https://api.openweathermap.org/data/2.5/weather?q=%s&units=imperial&appid=%s",
		url.QueryEscape(location), i.cfg.OpenWeatherKey)
	resp, err := i.http.Get(u)
	if err != nil {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "Weather lookup failed.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data struct {
		Name string `json:"name"`
		Main struct {
			Temp      float64 `json:"temp"`
			FeelsLike float64 `json:"feels_like"`
			Humidity  int     `json:"humidity"`
		} `json:"main"`
		Weather []struct{ Description string } `json:"weather"`
		Wind    struct{ Speed float64 }        `json:"wind"`
		Cod     int                            `json:"cod"`
	}
	if json.Unmarshal(body, &data) != nil || data.Cod != 200 {
		_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("Location not found: %s", location))
		return
	}
	desc := ""
	if len(data.Weather) > 0 {
		desc = data.Weather[0].Description
	}
	tempC := (data.Main.Temp - 32) * 5 / 9
	_ = s.SendPrivmsg(i.pc.Numeric, target,
		fmt.Sprintf("\x02%s:\x02 %s :: %.0f°F / %.0f°C :: Humidity: %d%% :: Wind: %.1f mph",
			data.Name, desc, data.Main.Temp, tempC, data.Main.Humidity, data.Wind.Speed))
}

func (i *Internets) forecast(s *server.Server, target, source string, args []string) {
	// Forecast uses the same API key as weather; 5-day/3-hour endpoint.
	if i.cfg.OpenWeatherKey == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "Forecast is not configured on this network.")
		return
	}
	_ = s.SendNotice(i.pc.Numeric, target, "Forecast: not yet implemented, use weather for now.")
	_ = source
	_ = args
}

func (i *Internets) registerLocation(s *server.Server, target, source string, args []string) {
	if len(args) == 0 {
		_ = s.SendNotice(i.pc.Numeric, target, "Usage: register_location <location>")
		return
	}
	u := s.Network().GetUser(source)
	if u == nil || u.Account == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "You must be logged in to an account to register a location.")
		return
	}
	location := strings.Join(args, " ")
	i.locMu.Lock()
	i.userLocs[strings.ToLower(u.Account)] = location
	i.locMu.Unlock()
	_ = s.SendNotice(i.pc.Numeric, target, fmt.Sprintf("Location registered: %s", location))
}

func (i *Internets) lookupRegisteredLocation(source string) string {
	i.locMu.RLock()
	defer i.locMu.RUnlock()
	// This module receives numerics; resolve to account through network lookup
	// done by caller. For now, return empty — weather() passes location directly.
	return ""
}

func (i *Internets) urbanDictionary(s *server.Server, target string, args []string) {
	if len(args) == 0 {
		_ = s.SendNotice(i.pc.Numeric, target, "Usage: ud <term>")
		return
	}
	term := strings.Join(args, " ")
	u := fmt.Sprintf("https://api.urbandictionary.com/v0/define?term=%s", url.QueryEscape(term))
	resp, err := i.http.Get(u)
	if err != nil {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "Urban Dictionary lookup failed.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data struct {
		List []struct {
			Word       string `json:"word"`
			Definition string `json:"definition"`
			Example    string `json:"example"`
		} `json:"list"`
	}
	if json.Unmarshal(body, &data) != nil || len(data.List) == 0 {
		_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("No definition found for %q.", term))
		return
	}
	d := data.List[0]
	def := strings.ReplaceAll(d.Definition, "\r\n", " ")
	def = strings.ReplaceAll(def, "\n", " ")
	if len(def) > 350 {
		def = def[:347] + "..."
	}
	_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("\x02%s:\x02 %s", d.Word, def))
}

func (i *Internets) qdb(s *server.Server, target string, args []string) {
	// Bash.org is defunct (closed 2023). QDB.us still operates. Using qdb.us.
	endpoint := "http://qdb.us/random?action=xml"
	if len(args) > 0 {
		if id, err := strconv.Atoi(args[0]); err == nil {
			endpoint = fmt.Sprintf("http://qdb.us/quote/%d?action=xml", id)
		}
	}
	resp, err := i.http.Get(endpoint)
	if err != nil {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "QDB is unreachable.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// Crude XML scrape — QDB's XML is minimal.
	txt := string(body)
	start := strings.Index(txt, "<quote")
	end := strings.Index(txt, "</quote>")
	if start < 0 || end < 0 {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "No quote returned.")
		return
	}
	_ = s.SendPrivmsg(i.pc.Numeric, target, "QDB quote retrieved — see https://qdb.us for full text.")
}

func (i *Internets) fml(s *server.Server, target string) {
	// FMyLife public API was discontinued; use their RSS feed instead.
	resp, err := i.http.Get("https://www.fmylife.com/rss/random.xml")
	if err != nil {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "FML is unreachable.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	txt := string(body)
	start := strings.Index(txt, "<description>")
	if start < 0 {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "No FML story found.")
		return
	}
	end := strings.Index(txt[start+13:], "</description>")
	if end < 0 {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "No FML story found.")
		return
	}
	story := txt[start+13 : start+13+end]
	if len(story) > 400 {
		story = story[:397] + "..."
	}
	_ = s.SendPrivmsg(i.pc.Numeric, target, "FML: "+story)
}

// -----------------------------------------------------------------------
// Stubs — commands that require API credentials or paid services
// -----------------------------------------------------------------------

func (i *Internets) steam(s *server.Server, target string, args []string) {
	if i.cfg.SteamKey == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "Steam is not configured on this network.")
		return
	}
	_ = s.SendNotice(i.pc.Numeric, target, "steam: implementation pending (ISteamUser/GetPlayerSummaries).")
	_ = args
}
func (i *Internets) lastfm(s *server.Server, target string, args []string) {
	if i.cfg.LastFMKey == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "LastFM is not configured on this network.")
		return
	}
	_ = s.SendNotice(i.pc.Numeric, target, "lastfm: implementation pending.")
	_ = args
}
func (i *Internets) imdb(s *server.Server, target string, args []string) {
	_ = s.SendNotice(i.pc.Numeric, target, "imdb: implementation pending (OMDb API required).")
	_ = args
}
func (i *Internets) twitch(s *server.Server, target string, args []string) {
	if i.cfg.TwitchClientID == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "Twitch is not configured on this network.")
		return
	}
	_ = s.SendNotice(i.pc.Numeric, target, "twitch: implementation pending (Helix API).")
	_ = args
}
func (i *Internets) youtube(s *server.Server, target string, args []string) {
	if i.cfg.YouTubeKey == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "YouTube is not configured on this network.")
		return
	}
	_ = s.SendNotice(i.pc.Numeric, target, "youtube: implementation pending (Data API v3).")
	_ = args
}
func (i *Internets) googleSearch(s *server.Server, target string, args []string, images bool) {
	if i.cfg.GoogleKey == "" || i.cfg.GoogleSearchCX == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "Google Search is not configured on this network.")
		return
	}
	_ = s.SendNotice(i.pc.Numeric, target, "google: implementation pending (Custom Search API).")
	_ = args
	_ = images
}
func (i *Internets) bingTranslate(s *server.Server, target string, args []string) {
	if i.cfg.BingKey == "" {
		_ = s.SendNotice(i.pc.Numeric, target, "Bing Translate is not configured on this network.")
		return
	}
	_ = s.SendNotice(i.pc.Numeric, target, "bing_translate: implementation pending.")
	_ = args
}
func (i *Internets) dictionary(s *server.Server, target string, args []string) {
	_ = s.SendNotice(i.pc.Numeric, target, "dictionary: implementation pending (Merriam-Webster API required).")
	_ = args
}
func (i *Internets) ipinfo(s *server.Server, target string, args []string) {
	if len(args) == 0 {
		_ = s.SendNotice(i.pc.Numeric, target, "Usage: ipinfo <ip>")
		return
	}
	// ipinfo.io has a free tier without key
	u := fmt.Sprintf("https://ipinfo.io/%s/json", url.QueryEscape(args[0]))
	resp, err := i.http.Get(u)
	if err != nil {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "ipinfo lookup failed.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data struct {
		IP, City, Region, Country, Org, Hostname string
	}
	if json.Unmarshal(body, &data) != nil {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "ipinfo parse error.")
		return
	}
	_ = s.SendPrivmsg(i.pc.Numeric, target,
		fmt.Sprintf("\x02%s\x02 (%s) — %s, %s, %s — %s",
			data.IP, data.Hostname, data.City, data.Region, data.Country, data.Org))
}
func (i *Internets) urlShorten(s *server.Server, target string, args []string) {
	_ = s.SendNotice(i.pc.Numeric, target, "url_shorten: implementation pending (goo.gl sunset, bit.ly API key required).")
	_ = args
}
func (i *Internets) urlExpand(s *server.Server, target string, args []string) {
	if len(args) == 0 {
		_ = s.SendNotice(i.pc.Numeric, target, "Usage: url_expand <short-url>")
		return
	}
	// Follow redirects manually
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Head(args[0])
	if err != nil {
		_ = s.SendPrivmsg(i.pc.Numeric, target, "URL unreachable.")
		return
	}
	defer resp.Body.Close()
	_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("Expanded: %s", resp.Request.URL.String()))
}

// evalSimpleExpr — left-to-right two-operand evaluator for calc.
func evalSimpleExpr(expr string) (string, error) {
	expr = strings.ReplaceAll(expr, " ", "")
	for _, op := range []string{"+", "-", "*", "/"} {
		if idx := strings.LastIndex(expr, op); idx > 0 {
			a, aerr := strconv.ParseFloat(expr[:idx], 64)
			b, berr := strconv.ParseFloat(expr[idx+1:], 64)
			if aerr != nil || berr != nil {
				continue
			}
			var r float64
			switch op {
			case "+":
				r = a + b
			case "-":
				r = a - b
			case "*":
				r = a * b
			case "/":
				if b == 0 {
					return "", fmt.Errorf("divide by zero")
				}
				r = a / b
			}
			return strconv.FormatFloat(r, 'f', -1, 64), nil
		}
	}
	return "", fmt.Errorf("unparseable expression")
}

// -----------------------------------------------------------------------
// BotServ toy commands (migrated from Synaxis mod-botserv.c).
//
// These eight commands historically lived in x3-lineage BotServ and were
// assignable per-channel via BotServ ASSIGN. Consolidating them here in
// Internets removes the double-reply case where both daemons respond to
// the same dot-prefix in a shared channel. The original Synaxis strings
// are preserved verbatim for behavior continuity.
// -----------------------------------------------------------------------

// roulette — russian roulette with per-channel chamber state.
// First pull loads the gun (1-in-6 chamber). Any subsequent pull while
// loaded kills the puller with the canonical BotServ message. This is
// faithful to x3's cmd_roulette: the first shooter is always safe, but
// stacking another pull on a loaded gun is always fatal.
func (i *Internets) roulette(s *server.Server, target, source string) {
	if !strings.HasPrefix(target, "#") && !strings.HasPrefix(target, "&") {
		_ = s.SendNotice(i.pc.Numeric, source, "Roulette is a channel game.")
		return
	}
	key := strings.ToLower(target)
	i.rouletteMu.Lock()
	loaded := i.rouletteChambers[key]
	if loaded != 0 {
		i.rouletteChambers[key] = 0 // reset
		i.rouletteMu.Unlock()
		u := s.Network().GetUser(source)
		victim := source
		if u != nil {
			victim = u.Nick
		}
		_ = s.SendPrivmsg(i.pc.Numeric, target,
			fmt.Sprintf("\x02%s\x02: BANG - Don't stuff bullets into a loaded gun", victim))
		// Synaxis's DelUser translates to a KILL. Noesis doesn't have direct
		// kill-user authority without an oper pseudo-client path; kick-equivalent
		// would need a channel op. Faithful-text-only port: announce, don't kill.
		// If you want actual kills, route through OperServ or Moo.
		return
	}
	// Load
	chamberR, _ := rand.Int(rand.Reader, big.NewInt(6))
	i.rouletteChambers[key] = int(chamberR.Int64()) + 1
	i.rouletteMu.Unlock()
	_ = s.SendPrivmsg(i.pc.Numeric, target, "\x01ACTION loads the gun and sets it on the table\x01")
}

func (i *Internets) botservUnf(s *server.Server, target, source string) {
	u := s.Network().GetUser(source)
	nick := source
	if u != nil {
		nick = u.Nick
	}
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		_ = s.SendPrivmsg(i.pc.Numeric, target,
			fmt.Sprintf("\x02%s\x02: I don't want to be part of your sick fantasies!", nick))
		return
	}
	_ = s.SendNotice(i.pc.Numeric, source, "I don't want to be part of your sick fantasies!")
}

func (i *Internets) botservPing(s *server.Server, target, source string) {
	u := s.Network().GetUser(source)
	nick := source
	if u != nil {
		nick = u.Nick
	}
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("\x02%s\x02: Pong!", nick))
		return
	}
	_ = s.SendNotice(i.pc.Numeric, source, "Pong!")
}

func (i *Internets) botservWut(s *server.Server, target, source string) {
	u := s.Network().GetUser(source)
	nick := source
	if u != nil {
		nick = u.Nick
	}
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("\x02%s\x02: wut", nick))
		return
	}
	_ = s.SendNotice(i.pc.Numeric, source, "wut")
}

func (i *Internets) botservHuggle(s *server.Server, target, source string) {
	u := s.Network().GetUser(source)
	nick := source
	if u != nil {
		nick = u.Nick
	}
	// CTCP ACTION must go via PRIVMSG (never NOTICE) per x3 comment.
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("\x01ACTION huggles %s\x01", nick))
		return
	}
	_ = s.SendPrivmsg(i.pc.Numeric, source, "\x01ACTION huggles you\x01")
}

func (i *Internets) botservReply(s *server.Server, target, source string, args []string) {
	if len(args) == 0 {
		_ = s.SendNotice(i.pc.Numeric, source, "Usage: reply <text>")
		return
	}
	u := s.Network().GetUser(source)
	nick := source
	if u != nil {
		nick = u.Nick
	}
	text := strings.Join(args, " ")
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		_ = s.SendPrivmsg(i.pc.Numeric, target, fmt.Sprintf("\x02%s\x02: %s", nick, text))
		return
	}
	_ = s.SendPrivmsg(i.pc.Numeric, source, text)
}
