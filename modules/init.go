// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/init.go — Module registration for the Noesis framework.
//
// Noesis ships with the service/fun/admin modules that correspond to
// Rizon's acid tree. The abuse/monitoring layer (formerly moo/mod_*) has
// been split out into Aegis — a separate consumer of the Noesis framework.
// Aegis registers its own modules on a Noesis server from its own main().

package modules

import (
	"log"

	"github.com/brandontroidl/noesis/server"
)

// RegisterAll registers all Noesis-shipped modules with the server.
// Downstream consumers (e.g. Aegis) may call their own registration on the
// same *server.Server after this returns.
func RegisterAll(s *server.Server) {
	sentinel := NewSentinel()

	mods := []server.Module{
		NewRootServ(),
		NewOperServ(),
		NewDroneScan(),
		NewFunServ(),
		NewLimitServ(),
		NewTrapBot(),
		NewVizon(),
		NewXmas(),
		NewQuotes(),
		NewTrivia(),
		NewInternets(),
		NewListBots(),
		NewRegistration(),
		NewCTCP(),
		NewStatServ(),
		sentinel,
	}

	for _, m := range mods {
		s.RegisterModule(m)
	}

	log.Printf("Noesis registered %d framework modules", len(mods))
}
