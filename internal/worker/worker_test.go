package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/mail"
	"path/filepath"
	"testing"
	"time"

	"github.com/dc9-dev/formd/internal/forms"
	fmail "github.com/dc9-dev/formd/internal/mail"
	"github.com/dc9-dev/formd/internal/store"
)

type fakeMailer struct {
	fail bool
	sent []fmail.Message
}

func (f *fakeMailer) Send(_ context.Context, m fmail.Message) error {
	if f.fail {
		return errors.New("smtp down")
	}
	f.sent = append(f.sent, m)
	return nil
}

func TestRetryAndCap(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := forms.NewDefinition("c")
	d.AllowedOrigins = []string{"https://example.com"}
	st.CreateForm(ctx, d)

	now := time.Now()
	mails := []store.OutMail{
		{Kind: "notify", To: "a@example.com", Subject: "1", Text: "x"},
		{Kind: "notify", To: "b@example.com", Subject: "2", Text: "x"},
		{Kind: "notify", To: "c@example.com", Subject: "3", Text: "x"},
	}
	if err := st.SaveSubmission(ctx, store.Submission{ID: store.NewID(), FormID: "c", Data: map[string]string{}, CreatedAt: now}, mails, "", time.Time{}); err != nil {
		t.Fatal(err)
	}

	fm := &fakeMailer{fail: true}
	w := New(st, fm, &mail.Address{Address: "from@example.com"}, 2, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if n := w.ProcessDue(ctx, now); n != 0 {
		t.Fatalf("sent %d while failing", n)
	}
	items, _ := st.RecentOutbox(ctx, "pending", 10)
	retried := 0
	for _, it := range items {
		if it.Attempts == 1 && it.NextAttemptAt.After(now) {
			retried++
		}
	}
	if len(items) != 3 || retried != 2 {
		t.Fatalf("want 2 of 3 scheduled for retry (cap limits batch), got %d: %+v", retried, items)
	}

	// Recover; cap of 2/hour limits delivery.
	fm.fail = false
	later := now.Add(2 * time.Minute)
	if n := w.ProcessDue(ctx, later); n != 2 {
		t.Fatalf("sent %d, want 2 (cap)", n)
	}
	if n := w.ProcessDue(ctx, later); n != 0 {
		t.Fatalf("cap exceeded: sent %d more", n)
	}
}
