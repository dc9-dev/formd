// Package worker delivers queued e-mails from the outbox with retries, and
// runs periodic maintenance (retention, expired sessions and nonces).
package worker

import (
	"context"
	"log/slog"
	"net/mail"
	"time"

	fmail "github.com/dc9-dev/formd/internal/mail"
	"github.com/dc9-dev/formd/internal/store"
)

var backoff = []time.Duration{
	time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour,
	6 * time.Hour, 12 * time.Hour, 24 * time.Hour,
}

// MaxAttempts after which a mail is marked failed.
var MaxAttempts = len(backoff) + 1

type Worker struct {
	Store     *store.Store
	Mailer    fmail.Mailer
	From      *mail.Address
	HourlyCap int
	Log       *slog.Logger

	wake chan struct{}
}

func New(s *store.Store, m fmail.Mailer, from *mail.Address, hourlyCap int, log *slog.Logger) *Worker {
	return &Worker{Store: s, Mailer: m, From: from, HourlyCap: hourlyCap, Log: log, wake: make(chan struct{}, 1)}
}

// Wake asks the worker to process the queue now (non-blocking).
func (w *Worker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *Worker) Run(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	maint := time.NewTicker(time.Hour)
	defer maint.Stop()
	w.maintain(ctx)
	for {
		w.ProcessDue(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		case <-tick.C:
		case <-maint.C:
			w.maintain(ctx)
		}
	}
}

func (w *Worker) maintain(ctx context.Context) {
	if err := w.Store.Cleanup(ctx, time.Now()); err != nil {
		w.Log.Error("maintenance failed", "err", err)
	}
}

// ProcessDue sends due mails, respecting the global hourly cap. Returns the
// number of mails sent.
func (w *Worker) ProcessDue(ctx context.Context, now time.Time) int {
	budget := 50
	if w.HourlyCap > 0 {
		sent, err := w.Store.CountSentSince(ctx, now.Add(-time.Hour))
		if err != nil {
			w.Log.Error("outbox: counting sent mail", "err", err)
			return 0
		}
		if left := w.HourlyCap - sent; left < budget {
			budget = left
		}
		if budget <= 0 {
			w.Log.Warn("outbox: MAIL_HOURLY_CAP reached, delaying delivery", "cap", w.HourlyCap)
			return 0
		}
	}
	items, err := w.Store.DueOutbox(ctx, now, budget)
	if err != nil {
		w.Log.Error("outbox: loading due mail", "err", err)
		return 0
	}
	sent := 0
	for _, it := range items {
		if ctx.Err() != nil {
			return sent
		}
		err := w.Mailer.Send(ctx, fmail.Message{
			From: w.From, To: it.To, ReplyTo: it.ReplyTo,
			Subject: it.Subject, Text: it.Text, HTML: it.HTML,
		})
		if err == nil {
			sent++
			if err := w.Store.MarkSent(ctx, it.ID, time.Now()); err != nil {
				w.Log.Error("outbox: mark sent", "id", it.ID, "err", err)
			}
			continue
		}
		attempt := it.Attempts + 1
		final := attempt >= MaxAttempts
		next := now
		if !final {
			next = now.Add(backoff[min(attempt-1, len(backoff)-1)])
		}
		msg := err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		w.Log.Warn("outbox: delivery failed", "id", it.ID, "kind", it.Kind, "attempt", attempt, "final", final, "err", msg)
		if err := w.Store.MarkRetry(ctx, it.ID, next, msg, final); err != nil {
			w.Log.Error("outbox: mark retry", "id", it.ID, "err", err)
		}
	}
	return sent
}
