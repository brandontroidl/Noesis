// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// config/config.go — TOML configuration for Acid.

package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration.
type Config struct {
	Server   ServerConfig   `toml:"server"`
	Uplink   UplinkConfig   `toml:"uplink"`
	Services ServicesConfig `toml:"services"`
	IRCv3    IRCv3Config    `toml:"ircv3"`
	Modules  ModulesConfig  `toml:"modules"`
	Debug    bool           `toml:"debug"`
}

// ServerConfig defines Acid's identity on the P10 network.
type ServerConfig struct {
	Name            string `toml:"name"`
	Numeric         int    `toml:"numeric"`
	Description     string `toml:"description"`
	MaxClients      int    `toml:"max_clients"`
	DBEncryptionKey string `toml:"db_encryption_key"`
}

// UplinkConfig defines the connection to Cathexis.
type UplinkConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Password string `toml:"password"`
	TLS      bool   `toml:"tls"`
	TLSCert  string `toml:"tls_cert"`
	TLSKey   string `toml:"tls_key"`
	TLSCA    string `toml:"tls_ca"`

	// S2S HMAC-SHA256 authentication
	HMACKey       string `toml:"hmac_key"`
	HMACScheme    string `toml:"hmac_scheme"`    // cathexis-s2s-hmac-sha3-v2 (default, for Cathexis 1.6.0+) or cathexis-s2s-hmac-v1 (legacy)
	HMACKeyDerive string `toml:"hmac_key_derive"` // key derivation method

	// TLS verification — set true for self-signed certs or IP-only connections
	TLSSkipVerify bool `toml:"tls_skip_verify"`
}

// ServicesConfig defines Acid's service pseudo-clients.
type ServicesConfig struct {
	// Global prefix for service commands (e.g., "!")
	Prefix string `toml:"prefix"`

	// Privilege tiers (7 levels)
	Privileges PrivilegeConfig `toml:"privileges"`

	// Flood control
	Flood FloodConfig `toml:"flood"`
}

// PrivilegeConfig defines the 7-tier privilege system.
type PrivilegeConfig struct {
	// Tier 1: Network owner
	Owners []string `toml:"owners"`
	// Tier 2: Network admins
	Admins []string `toml:"admins"`
	// Tier 3: IRC operators
	Opers []string `toml:"opers"`
	// Tier 4: Channel service admins
	ChanAdmins []string `toml:"chan_admins"`
	// Tier 5: Helpers
	Helpers []string `toml:"helpers"`
	// Tier 6: Authenticated users
	// (all logged-in users)
	// Tier 7: Unauthenticated users
	// (everyone else)
}

// FloodConfig controls rate limiting for service commands.
type FloodConfig struct {
	MaxPerSecond  int `toml:"max_per_second"`
	MaxBurst      int `toml:"max_burst"`
	CooldownSecs  int `toml:"cooldown_secs"`
}

// IRCv3Config controls IRCv3 feature enablement.
type IRCv3Config struct {
	// EnableTags enables IRCv3 message tag generation on outgoing P10 lines.
	EnableTags bool `toml:"enable_tags"`

	// EnableBotMode sets +B on all pseudo-clients.
	EnableBotMode bool `toml:"enable_bot_mode"`

	// EnableChathistory enables CHATHISTORY XQUERY handling.
	EnableChathistory bool `toml:"enable_chathistory"`

	// MaxHistoryPerChannel is the max stored messages per channel (default 10000).
	MaxHistoryPerChannel int `toml:"max_history_per_channel"`
}

// ModulesConfig defines per-module settings.
type ModulesConfig struct {
	Trivia    TriviaModuleConfig  `toml:"trivia"`
	Quotes    QuotesModuleConfig  `toml:"quotes"`
	LimitServ LimitServConfig     `toml:"limitserv"`
	TrapBot   TrapBotConfig       `toml:"trapbot"`
	CTCP      CTCPConfig          `toml:"ctcp"`
	Vizon     VizonConfig         `toml:"vizon"`
	Xmas      XmasConfig          `toml:"xmas"`
	RootServ  RootServConfig      `toml:"rootserv"`
	Moo       MooConfig           `toml:"moo"`
	DroneScan DroneScanConfig     `toml:"dronescan"`
	DNSBL     DNSBLConfig         `toml:"dnsbl"`
	ProxyScan ProxyScanConfig     `toml:"proxyscan"`
	MXBL      MXBLConfig          `toml:"mxbl"`
	Track     TrackConfig         `toml:"track"`
	Watch     WatchConfig         `toml:"watch"`
	Webhooks  WebhooksConfig      `toml:"webhooks"`
	OSFlood   OSFloodConfig       `toml:"osflood"`
	AntiIdle  AntiIdleConfig      `toml:"antiidle"`
	OperServ  OperServConfig      `toml:"operserv"`
	ChanLog   ChanLogConfig       `toml:"chanlog"`
	StatServ  StatServConfig      `toml:"statserv"`
	FunServ      FunServConfig      `toml:"funserv"`
	Sentinel     SentinelConfig     `toml:"sentinel"`
	ListBots     ListBotsConfig     `toml:"listbots"`
	Registration RegistrationConfig `toml:"registration"`
	Internets    InternetsConfig    `toml:"internets"`
}

// FunServConfig — Rizon-style FunServ broker settings.
// FunServ no longer owns weather/trivia state; those live on the assignable
// bots (Internets, Trivia). This config is now purely presentation.
type FunServConfig struct {
	Enabled bool   `toml:"enabled"`
	Nick    string `toml:"nick"`
	Ident   string `toml:"ident"`
	Gecos   string `toml:"gecos"`
	// WeatherKey and TriviaTime were used by the pre-1.9.0 monolithic FunServ
	// and are ignored as of 1.9.0. Set OpenWeatherKey on [modules.internets]
	// and round_time on [modules.trivia] instead. Kept for backward-compat
	// TOML parsing; silently ignored at runtime.
	WeatherKey string `toml:"weather_key"`
	TriviaTime int    `toml:"trivia_time"`
}

// StatServConfig holds network statistics service settings.
type StatServConfig struct {
	Enabled  bool     `toml:"enabled"`
	Nick     string   `toml:"nick"`
	Ident    string   `toml:"ident"`
	Gecos    string   `toml:"gecos"`
	LogDir   string   `toml:"log_dir"`
	HTTPAddr string   `toml:"http_addr"`
	Channels []string `toml:"channels"`
}

// TriviaModuleConfig holds trivia module settings.
type TriviaModuleConfig struct {
	Enabled      bool   `toml:"enabled"`
	Nick         string `toml:"nick"`
	Ident        string `toml:"ident"`
	Gecos        string `toml:"gecos"`
	QuestionFile string `toml:"question_file"`
	RoundTime    int    `toml:"round_time"`
}

// QuotesModuleConfig holds quotes module settings.
type QuotesModuleConfig struct {
	Enabled  bool   `toml:"enabled"`
	Nick     string `toml:"nick"`
	Ident    string `toml:"ident"`
	Gecos    string `toml:"gecos"`
	DataFile string `toml:"data_file"`
}

// LimitServConfig holds channel limit enforcement settings.
type LimitServConfig struct {
	Enabled    bool   `toml:"enabled"`
	Nick       string `toml:"nick"`
	Ident      string `toml:"ident"`
	Gecos      string `toml:"gecos"`
	Padding    int    `toml:"padding"`
	Interval   int    `toml:"interval"`
}

// TrapBotConfig holds trap/honeypot channel settings.
type TrapBotConfig struct {
	Enabled  bool     `toml:"enabled"`
	Nick     string   `toml:"nick"`
	Ident    string   `toml:"ident"`
	Gecos    string   `toml:"gecos"`
	Channels []string `toml:"channels"`
	Action   string   `toml:"action"` // gline, kline, kill
	Duration int      `toml:"duration"`
	Reason   string   `toml:"reason"`
}

// CTCPConfig holds CTCP response settings.
type CTCPConfig struct {
	Enabled     bool   `toml:"enabled"`
	VersionReply string `toml:"version_reply"`
}

// VizonConfig holds vizon module settings.
type VizonConfig struct {
	Enabled bool   `toml:"enabled"`
	Nick    string `toml:"nick"`
	Ident   string `toml:"ident"`
	Gecos   string `toml:"gecos"`
}

// XmasConfig holds seasonal event settings (Rizon-lineage: xmas/Xmas.java).
type XmasConfig struct {
	Enabled bool   `toml:"enabled"`
	Nick    string `toml:"nick"`
	Ident   string `toml:"ident"`
	Gecos   string `toml:"gecos"`
}

type RootServConfig struct {
	Enabled       bool     `toml:"enabled"`
	Nick          string   `toml:"nick"`
	Ident         string   `toml:"ident"`
	Gecos         string   `toml:"gecos"`
	AdminChannels []string `toml:"admin_channels"`
	RootAccounts  []string `toml:"root_accounts"`
	AdminAccounts []string `toml:"admin_accounts"`
	AuditDB       string   `toml:"audit_db"`
}

type MooConfig struct {
	Enabled       bool     `toml:"enabled"`
	Nick          string   `toml:"nick"`
	Ident         string   `toml:"ident"`
	Gecos         string   `toml:"gecos"`
	OperChannels  []string `toml:"oper_channels"`
	AdminChannels []string `toml:"admin_channels"`
	StaffChannels []string `toml:"staff_channels"`
	SpamChannels  []string `toml:"spam_channels"`
	FloodChannels []string `toml:"flood_channels"`
	SplitChannels []string `toml:"split_channels"`
	LogChannels   []string `toml:"log_channels"`
	KlineChannels []string `toml:"kline_channels"`
	Database      string   `toml:"database"`
}

type DroneScanConfig struct {
	Enabled              bool     `toml:"enabled"`
	Nick                 string   `toml:"nick"`
	Ident                string   `toml:"ident"`
	Gecos                string   `toml:"gecos"`
	AlertChannel         string   `toml:"alert_channel"`
	NickEntropyThreshold float64  `toml:"nick_entropy_threshold"`
	CloneThreshold       int      `toml:"clone_threshold"`
	MassJoinThreshold    int      `toml:"mass_join_threshold"`
	MassJoinWindowSecs   int      `toml:"mass_join_window_secs"`
	AutoGline            bool     `toml:"auto_gline"`
	GlineDuration        int      `toml:"gline_duration"`
	GlineReason          string   `toml:"gline_reason"`
	ExemptChannels       []string `toml:"exempt_channels"`
}

type DNSBLConfig struct {
	Enabled        bool       `toml:"enabled"`
	Zones          []DNSBLZone `toml:"zones"`
	WarnThreshold  int        `toml:"warn_threshold"`
	GlineThreshold int        `toml:"gline_threshold"`
	GlineDuration  int        `toml:"gline_duration"`
	GlineReason    string     `toml:"gline_reason"`
	CacheTTLSecs   int        `toml:"cache_ttl_secs"`
	CacheDatabase  string     `toml:"cache_database"`
	AlertChannel   string     `toml:"alert_channel"`
}

type DNSBLZone struct {
	Zone        string `toml:"zone"`
	Weight      int    `toml:"weight"`
	Description string `toml:"description"`
	Mask        int    `toml:"mask"`
}

type ProxyScanConfig struct {
	Enabled       bool   `toml:"enabled"`
	ScanSOCKS4    bool   `toml:"scan_socks4"`
	ScanSOCKS5    bool   `toml:"scan_socks5"`
	ScanHTTP      bool   `toml:"scan_http"`
	SOCKS4Ports   []int  `toml:"socks4_ports"`
	SOCKS5Ports   []int  `toml:"socks5_ports"`
	HTTPPorts     []int  `toml:"http_ports"`
	TargetHost    string `toml:"target_host"`
	TargetPort    int    `toml:"target_port"`
	TimeoutSecs   int    `toml:"timeout_secs"`
	MaxConcurrent int    `toml:"max_concurrent"`
	GlineDuration int    `toml:"gline_duration"`
	GlineReason   string `toml:"gline_reason"`
	DroneBLEnabled bool  `toml:"dronebl_enabled"`
	DroneBLKey    string `toml:"dronebl_key"`
	CacheTTLSecs  int    `toml:"cache_ttl_secs"`
	CacheDatabase string `toml:"cache_database"`
	AlertChannel  string `toml:"alert_channel"`
}

type MXBLConfig struct {
	Enabled            bool     `toml:"enabled"`
	BlacklistedDomains []string `toml:"blacklisted_domains"`
	AlertChannel       string   `toml:"alert_channel"`
}

type TrackConfig struct {
	Enabled       bool   `toml:"enabled"`
	Channel       string `toml:"channel"`
	TrackNick     bool   `toml:"track_nick"`
	TrackJoin     bool   `toml:"track_join"`
	TrackPart     bool   `toml:"track_part"`
	TrackKick     bool   `toml:"track_kick"`
	TrackNew      bool   `toml:"track_new"`
	TrackQuit     bool   `toml:"track_quit"`
	TrackAuth     bool   `toml:"track_auth"`
	TrackChanmode bool   `toml:"track_chanmode"`
	TrackUmode    bool   `toml:"track_umode"`
	ShowBursts    bool   `toml:"show_bursts"`
}

type ChanLogConfig struct {
	Enabled  bool     `toml:"enabled"`
	LogDir   string   `toml:"log_dir"`
	Channels []string `toml:"channels"`
}

type WatchConfig struct {
	Enabled      bool   `toml:"enabled"`
	AlertChannel string `toml:"alert_channel"`
	Database     string `toml:"database"`
}

type WebhooksConfig struct {
	Enabled        bool   `toml:"enabled"`
	ListenAddr     string `toml:"listen_addr"`
	GitLabSecret   string `toml:"gitlab_secret"`
	GrafanaSecret  string `toml:"grafana_secret"`
	CommitChannel  string `toml:"commit_channel"`
	GrafanaChannel string `toml:"grafana_channel"`
}

type OSFloodConfig struct {
	Enabled      bool   `toml:"enabled"`
	Threshold    int    `toml:"threshold"`
	WindowSecs   int    `toml:"window_secs"`
	AlertChannel string `toml:"alert_channel"`
}

type AntiIdleConfig struct {
	Enabled           bool     `toml:"enabled"`
	Channels          []string `toml:"channels"`
	IdleThresholdSecs int      `toml:"idle_threshold_secs"`
	KickThresholdSecs int      `toml:"kick_threshold_secs"`
	CheckIntervalSecs int      `toml:"check_interval_secs"`
}

type OperServConfig struct {
	Enabled  bool     `toml:"enabled"`
	Nick     string   `toml:"nick"`
	Ident    string   `toml:"ident"`
	Gecos    string   `toml:"gecos"`
	Channels []string `toml:"channels"`
	Database string   `toml:"database"`
}

type SentinelConfig struct {
	Enabled       bool           `toml:"enabled"`
	Nick          string         `toml:"nick"`
	Ident         string         `toml:"ident"`
	Gecos         string         `toml:"gecos"`
	AlertChannel  string         `toml:"alert_channel"`
	CerberusURL   string         `toml:"cerberus_url"`
	CerberusKey   string         `toml:"cerberus_key"`
	ListThreshold int            `toml:"list_threshold"`
	DecaySecs     int            `toml:"decay_secs"`
	AutoGline     bool           `toml:"auto_gline"`
	GlineDuration int            `toml:"gline_duration"`
	GlineReason   string         `toml:"gline_reason"`
	TTLHours      int            `toml:"ttl_hours"`
	ExemptIPs     []string       `toml:"exempt_ips"`
	Rules         []SentinelRule `toml:"rules"`

	// DNSBL weighted-scoring layer. Cathexis IRCd handles the actual
	// zone lookups in s_auth.c (up to 3 zones, binary listed/not-listed)
	// and emits an extended MARK with pipe-separated zone names:
	//   MARK <client> DNSBL|dnsbl.dronebl.org|rbl.efnetrbl.org
	// Sentinel parses the zone list, applies configured weights, and
	// escalates (warn, gline) on threshold breach.
	DNSBLScoring DNSBLScoringConfig `toml:"dnsbl_scoring"`
}

// DNSBLScoringConfig controls how Sentinel weights multi-zone DNSBL marks.
// Set Enabled=true and keep Cathexis's FEAT_DNSBL_REJECT=false so listed
// clients get marked (not kicked). Sentinel then scores and decides whether
// they warrant a gline.
type DNSBLScoringConfig struct {
	Enabled        bool              `toml:"enabled"`
	WarnThreshold  int               `toml:"warn_threshold"`
	GlineThreshold int               `toml:"gline_threshold"`
	GlineDuration  int               `toml:"gline_duration"`  // seconds
	GlineReason    string            `toml:"gline_reason"`
	MarkPrefix     string            `toml:"mark_prefix"`      // matches Cathexis FEAT_DNSBL_MARK, default "DNSBL"
	AlertChannel   string            `toml:"alert_channel"`    // empty falls back to SentinelConfig.AlertChannel
	Zones          []DNSBLZoneWeight `toml:"zones"`
}

type DNSBLZoneWeight struct {
	Zone        string `toml:"zone"`
	Weight      int    `toml:"weight"`
	Description string `toml:"description"`
}

type SentinelRule struct {
	Name       string `toml:"name"`
	Event      string `toml:"event"`
	Threshold  int    `toml:"threshold"`
	WindowSecs int    `toml:"window_secs"`
	Score      int    `toml:"score"`
	Category   int    `toml:"category"`
}

// Load reads and parses a TOML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		// Defaults
		IRCv3: IRCv3Config{
			EnableTags:    true,
			EnableBotMode: true,
		},
		Services: ServicesConfig{
			Prefix: "!",
			Flood: FloodConfig{
				MaxPerSecond: 5,
				MaxBurst:     10,
				CooldownSecs: 30,
			},
		},
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// validate checks required fields.
func (c *Config) validate() error {
	if c.Server.Name == "" {
		return fmt.Errorf("server.name is required")
	}
	if c.Server.Numeric < 0 || c.Server.Numeric > 4095 {
		return fmt.Errorf("server.numeric must be 0-4095")
	}
	if c.Uplink.Host == "" {
		return fmt.Errorf("uplink.host is required")
	}
	if c.Uplink.Port <= 0 || c.Uplink.Port > 65535 {
		return fmt.Errorf("uplink.port must be 1-65535")
	}
	if c.Uplink.Password == "" {
		return fmt.Errorf("uplink.password is required")
	}
	return nil
}

// ListBotsConfig — pseudo-client directory service (Rizon pyva/listbots lineage).
type ListBotsConfig struct {
	Enabled  bool   `toml:"enabled"`
	Nick     string `toml:"nick"`
	Ident    string `toml:"ident"`
	Gecos    string `toml:"gecos"`
	DataFile string `toml:"data_file"`
}

// RegistrationConfig — channel registration greeter (Rizon pyva/registration lineage).
type RegistrationConfig struct {
	Enabled      bool     `toml:"enabled"`
	Nick         string   `toml:"nick"`
	Ident        string   `toml:"ident"`
	Gecos        string   `toml:"gecos"`
	WelcomeLines []string `toml:"welcome_lines"`
	LogChannel   string   `toml:"log_channel"`
}

// InternetsConfig — Rizon Internets bot (search/utility).
// Commands requiring external API credentials use these fields; commands
// without configured keys reply with a "not configured" notice.
type InternetsConfig struct {
	Enabled          bool   `toml:"enabled"`
	Nick             string `toml:"nick"`
	Ident            string `toml:"ident"`
	Gecos            string `toml:"gecos"`
	OpenWeatherKey   string `toml:"openweather_key"`
	GoogleKey        string `toml:"google_key"`
	GoogleSearchCX   string `toml:"google_search_cx"`
	BingKey          string `toml:"bing_key"`
	SteamKey         string `toml:"steam_key"`
	LastFMKey        string `toml:"lastfm_key"`
	TwitchClientID   string `toml:"twitch_client_id"`
	TwitchSecret     string `toml:"twitch_secret"`
	YouTubeKey       string `toml:"youtube_key"`
	WolframAppID     string `toml:"wolfram_app_id"`
}
