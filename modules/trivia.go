// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/trivia.go — Trivia game service module.

package modules

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

// Built-in trivia question bank: [question, answer]
var triviaQuestions = [][2]string{
	{"What is the capital of France?", "paris"},
	{"What planet is closest to the Sun?", "mercury"},
	{"What year did the Titanic sink?", "1912"},
	{"What is the chemical symbol for gold?", "au"},
	{"How many bits in a byte?", "8"},
	{"What protocol does IRC use at the transport layer?", "tcp"},
	{"What port is traditionally used for IRC?", "6667"},
	{"What RFC originally defined IRC?", "1459"},
	{"What does TLS stand for?", "transport layer security"},
	{"What is the largest ocean on Earth?", "pacific"},
	{"In what year was Linux first released?", "1991"},
	{"What does CPU stand for?", "central processing unit"},
	{"What language is the Linux kernel written in?", "c"},
	{"What is the speed of light in km/s (rounded)?", "300000"},
	{"How many planets are in our solar system?", "8"},
	{"What does DNS stand for?", "domain name system"},
	{"What is the smallest prime number?", "2"},
	{"What color do you get mixing red and blue?", "purple"},
	{"What does HTTP stand for?", "hypertext transfer protocol"},
	{"What year was the first iPhone released?", "2007"},
}

// Trivia provides an interactive trivia game.
type Trivia struct {
	pc        *server.PseudoClient
	mu        sync.Mutex
	active    map[string]*TriviaGame // channel -> active game
	roundTime int
}

// TriviaGame tracks an active trivia round.
type TriviaGame struct {
	Channel    string
	Question   string
	Answer     string
	StartTime  time.Time
	Scores     map[string]int // nick -> score
}

func NewTrivia() *Trivia {
	return &Trivia{
		active: make(map[string]*TriviaGame),
	}
}

func (t *Trivia) Name() string { return "trivia" }

func (t *Trivia) Init(s *server.Server) error {
	cfg := s.Config().Modules.Trivia
	if !cfg.Enabled {
		log.Printf("[%s] disabled", t.Name())
		return nil
	}

	t.roundTime = cfg.RoundTime
	if t.roundTime <= 0 {
		t.roundTime = 30
	}

	nick := cfg.Nick
	if nick == "" {
		nick = "TriviaBot"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "trivia"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Trivia Game Service"
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, t)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	t.pc = pc

	log.Printf("[%s] initialized as %s (%s)", t.Name(), nick, pc.Numeric)
	return nil
}

func (t *Trivia) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if t.pc == nil {
		return
	}

	text := msg.Trailing()
	prefix := s.Config().Services.Prefix
	target := msg.Param(0)

	switch {
	case strings.HasPrefix(text, prefix+"trivia start"):
		t.startGame(s, target)
	case strings.HasPrefix(text, prefix+"trivia stop"):
		t.stopGame(s, target)
	case strings.HasPrefix(text, prefix+"trivia score"):
		t.showScores(s, target)
	default:
		// Check for answer attempts in active games
		t.checkAnswer(s, msg, target)
	}
}

func (t *Trivia) startGame(s *server.Server, channel string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, active := t.active[channel]; active {
		s.SendPrivmsg(t.pc.Numeric, channel, "A trivia game is already running!")
		return
	}

	game := &TriviaGame{
		Channel:   channel,
		StartTime: time.Now(),
		Scores:    make(map[string]int),
	}

	// Pick a random question from the built-in bank
	q := triviaQuestions[rand.Intn(len(triviaQuestions))]
	game.Question = q[0]
	game.Answer = q[1]
	t.active[channel] = game

	s.SendPrivmsg(t.pc.Numeric, channel, fmt.Sprintf("Trivia started! You have %d seconds per question.", t.roundTime))
	s.SendPrivmsg(t.pc.Numeric, channel, fmt.Sprintf("Question: %s", game.Question))
}

func (t *Trivia) stopGame(s *server.Server, channel string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, active := t.active[channel]; !active {
		s.SendPrivmsg(t.pc.Numeric, channel, "No trivia game is running.")
		return
	}

	delete(t.active, channel)
	s.SendPrivmsg(t.pc.Numeric, channel, "Trivia game stopped.")
}

func (t *Trivia) checkAnswer(s *server.Server, msg *ircv3.P10Message, channel string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	game, active := t.active[channel]
	if !active {
		return
	}

	text := strings.TrimSpace(strings.ToLower(msg.Trailing()))
	if text == game.Answer {
		nick := msg.Source
		if u := s.Network().GetUser(msg.Source); u != nil {
			nick = u.Nick
		}
		game.Scores[nick]++
		s.SendPrivmsg(t.pc.Numeric, channel,
			fmt.Sprintf("Correct, %s! Score: %d", nick, game.Scores[nick]))
	}
}

func (t *Trivia) showScores(s *server.Server, channel string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	game, active := t.active[channel]
	if !active {
		s.SendPrivmsg(t.pc.Numeric, channel, "No trivia game is running.")
		return
	}

	if len(game.Scores) == 0 {
		s.SendPrivmsg(t.pc.Numeric, channel, "No scores yet.")
		return
	}

	s.SendPrivmsg(t.pc.Numeric, channel, "Scores:")
	for nick, score := range game.Scores {
		s.SendPrivmsg(t.pc.Numeric, channel, fmt.Sprintf("  %s: %d", nick, score))
	}
}

func (t *Trivia) Shutdown() {
	log.Printf("[%s] shutdown", t.Name())
}
