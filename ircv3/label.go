// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// ircv3/label.go — IRCv3 labeled-response support for P10 relay.
//
// When a client sends a command with a label= tag, Cathexis may relay
// that label through P10 to Acid (e.g., on an XQUERY). Acid must echo
// the label= tag on all response messages so Cathexis can correlate
// them back to the originating client command.
//
// If the response is multi-message, Acid wraps it in a
// labeled-response batch:
//   BATCH +refid labeled-response
//   @batch=refid ... response 1 ...
//   @batch=refid ... response 2 ...
//   BATCH -refid
//
// If the response is a single message, just echo the label tag directly.

package ircv3

// LabelContext holds the label from an incoming labeled command.
// Pass this through the handler chain so response builders can
// attach the label to their output.
type LabelContext struct {
	// Label is the label value from the incoming @label= tag.
	// Empty string means no label was present.
	Label string

	// ResponseCount tracks how many response messages have been
	// generated. If > 1, we need a labeled-response batch.
	ResponseCount int

	// BatchRefID is set when a labeled-response batch has been
	// opened (ResponseCount > 1). Empty if no batch needed yet.
	BatchRefID string
}

// NewLabelContext creates a LabelContext from an incoming message's tags.
// Returns nil if no label tag is present.
func NewLabelContext(tags *Tags) *LabelContext {
	if tags == nil {
		return nil
	}
	label, ok := tags.Get("label")
	if !ok || label == "" {
		return nil
	}
	return &LabelContext{Label: label}
}

// HasLabel returns true if this context has an active label.
func (lc *LabelContext) HasLabel() bool {
	return lc != nil && lc.Label != ""
}

// NeedsBatch returns true if we've generated multiple responses
// and need to wrap them in a labeled-response batch.
func (lc *LabelContext) NeedsBatch() bool {
	return lc != nil && lc.ResponseCount > 1
}

// ApplyToMessage applies the label context to an outgoing message.
// For single responses: sets @label= tag.
// For multi responses: sets @batch= tag (batch must be opened separately).
func (lc *LabelContext) ApplyToMessage(msg *P10Message) {
	if lc == nil || lc.Label == "" {
		return
	}
	msg.EnsureTags()

	if lc.BatchRefID != "" {
		// Inside a labeled-response batch — use batch reference
		msg.Tags.Set("batch", lc.BatchRefID)
	} else if lc.ResponseCount <= 1 {
		// Single response — echo label directly
		msg.Tags.Set("label", lc.Label)
	}
}

// StartBatch generates a BATCH +refid labeled-response line.
// Call this before sending the second response message.
// Returns the P10Message for the BATCH start command.
func (lc *LabelContext) StartBatch(serverNumeric string) *P10Message {
	if lc == nil || lc.Label == "" {
		return nil
	}
	lc.BatchRefID = GenerateRefID()
	msg := &P10Message{
		Tags:    NewTags(),
		Source:  serverNumeric,
		Command: "BA", // BATCH token in P10
		Params:  []string{"+" + lc.BatchRefID, BatchLabeledResponse},
	}
	msg.Tags.Set("label", lc.Label)
	return msg
}

// EndBatch generates a BATCH -refid line.
// Call this after all response messages have been sent.
func (lc *LabelContext) EndBatch(serverNumeric string) *P10Message {
	if lc == nil || lc.BatchRefID == "" {
		return nil
	}
	return &P10Message{
		Source:  serverNumeric,
		Command: "BA", // BATCH token in P10
		Params:  []string{"-" + lc.BatchRefID},
	}
}

// IncrementResponse tracks that we're about to send another response.
// Returns true if this is the first response that triggers batch mode
// (i.e., the transition from 1→2 responses).
func (lc *LabelContext) IncrementResponse() bool {
	if lc == nil {
		return false
	}
	lc.ResponseCount++
	return lc.ResponseCount == 2
}
