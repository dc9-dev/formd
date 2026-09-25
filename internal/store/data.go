package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dc9-dev/formd/internal/forms"
)

// ---- forms ----

type FormRow struct {
	Def       forms.Definition
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (s *Store) ListForms(ctx context.Context) ([]FormRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT definition, created_at, updated_at FROM forms ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FormRow
	for rows.Next() {
		var raw string
		var c, u int64
		if err := rows.Scan(&raw, &c, &u); err != nil {
			return nil, err
		}
		var r FormRow
		if err := json.Unmarshal([]byte(raw), &r.Def); err != nil {
			return nil, err
		}
		r.CreatedAt, r.UpdatedAt = time.Unix(c, 0), time.Unix(u, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetForm(ctx context.Context, id string) (forms.Definition, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT definition FROM forms WHERE id = ?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return forms.Definition{}, ErrNotFound
	}
	if err != nil {
		return forms.Definition{}, err
	}
	var d forms.Definition
	return d, json.Unmarshal([]byte(raw), &d)
}

var ErrExists = errors.New("already exists")

func (s *Store) CreateForm(ctx context.Context, d forms.Definition) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO forms(id, definition, created_at, updated_at) VALUES(?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`, d.ID, string(raw), now, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrExists
	}
	return nil
}

func (s *Store) UpdateForm(ctx context.Context, d forms.Definition) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE forms SET definition = ?, updated_at = ? WHERE id = ?`, string(raw), time.Now().Unix(), d.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteForm(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE form_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM forms WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- submissions ----

type Submission struct {
	ID          string
	FormID      string
	Data        map[string]string
	ContentHash string
	IP          string
	UserAgent   string
	CreatedAt   time.Time
}

type OutMail struct {
	Kind    string // notify | confirm
	To      string
	ReplyTo string
	Subject string
	Text    string
	HTML    string
}

// SaveSubmission stores a submission and its e-mails atomically, so mail is
// never lost if delivery fails later. The challenge nonce (if any) is spent in
// the same transaction; a replayed nonce aborts everything with ErrReplay.
func (s *Store) SaveSubmission(ctx context.Context, sub Submission, mails []OutMail, nonce string, nonceExpiry time.Time) error {
	data, err := json.Marshal(sub.Data)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if nonce != "" {
		if err := spendNonce(ctx, tx, nonce, nonceExpiry); err != nil {
			return err
		}
	}
	now := sub.CreatedAt.Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO submissions(id, form_id, data, content_hash, ip, user_agent, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		sub.ID, sub.FormID, string(data), sub.ContentHash, sub.IP, sub.UserAgent, now); err != nil {
		return err
	}
	for _, m := range mails {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO outbox(submission_id, form_id, kind, to_addr, reply_to, subject, body_text, body_html, next_attempt_at, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sub.ID, sub.FormID, m.Kind, m.To, m.ReplyTo, m.Subject, m.Text, m.HTML, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var ErrReplay = errors.New("challenge already used")

// SpendNonce records a challenge nonce outside of a submission (used when a
// submission is silently dropped as spam, so the token still cannot be reused).
func (s *Store) SpendNonce(ctx context.Context, nonce string, expiry time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := spendNonce(ctx, tx, nonce, expiry); err != nil {
		return err
	}
	return tx.Commit()
}

func spendNonce(ctx context.Context, tx *sql.Tx, nonce string, expiry time.Time) error {
	res, err := tx.ExecContext(ctx, `INSERT INTO used_challenges(nonce, expires_at) VALUES(?, ?) ON CONFLICT(nonce) DO NOTHING`, nonce, expiry.Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrReplay
	}
	return nil
}

func (s *Store) CountSubmissionsSince(ctx context.Context, formID string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM submissions WHERE form_id = ? AND created_at >= ?`, formID, since.Unix()).Scan(&n)
	return n, err
}

func (s *Store) DuplicateExists(ctx context.Context, formID, hash string, since time.Time) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM submissions WHERE form_id = ? AND content_hash = ? AND created_at >= ? LIMIT 1`, formID, hash, since.Unix()).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) CountMailsTo(ctx context.Context, kind, to string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE kind = ? AND to_addr = ? COLLATE NOCASE AND created_at >= ?`, kind, to, since.Unix()).Scan(&n)
	return n, err
}

func (s *Store) ListSubmissions(ctx context.Context, formID string, since time.Time, limit, offset int) ([]Submission, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, form_id, data, content_hash, ip, user_agent, created_at FROM submissions
		 WHERE form_id = ? AND created_at >= ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?`,
		formID, since.Unix(), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Submission
	for rows.Next() {
		var sub Submission
		var data string
		var ts int64
		if err := rows.Scan(&sub.ID, &sub.FormID, &data, &sub.ContentHash, &sub.IP, &sub.UserAgent, &ts); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &sub.Data); err != nil {
			return nil, err
		}
		sub.CreatedAt = time.Unix(ts, 0)
		out = append(out, sub)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSubmission(ctx context.Context, formID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM submissions WHERE form_id = ? AND id = ?`, formID, id)
	return err
}

func (s *Store) CountSubmissions(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT form_id, COUNT(*) FROM submissions GROUP BY form_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// ---- outbox ----

type OutboxItem struct {
	ID            int64
	SubmissionID  sql.NullString
	FormID        string
	Kind          string
	To            string
	ReplyTo       string
	Subject       string
	Text          string
	HTML          string
	Status        string
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
	CreatedAt     time.Time
	SentAt        sql.NullInt64
}

const outboxCols = `id, submission_id, form_id, kind, to_addr, reply_to, subject, body_text, body_html, status, attempts, next_attempt_at, last_error, created_at, sent_at`

func scanOutbox(rows *sql.Rows) ([]OutboxItem, error) {
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var it OutboxItem
		var next, created int64
		if err := rows.Scan(&it.ID, &it.SubmissionID, &it.FormID, &it.Kind, &it.To, &it.ReplyTo, &it.Subject, &it.Text, &it.HTML,
			&it.Status, &it.Attempts, &next, &it.LastError, &created, &it.SentAt); err != nil {
			return nil, err
		}
		it.NextAttemptAt, it.CreatedAt = time.Unix(next, 0), time.Unix(created, 0)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) DueOutbox(ctx context.Context, now time.Time, limit int) ([]OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+outboxCols+` FROM outbox WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT ?`, now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	return scanOutbox(rows)
}

func (s *Store) RecentOutbox(ctx context.Context, status string, limit int) ([]OutboxItem, error) {
	q := `SELECT ` + outboxCols + ` FROM outbox`
	args := []any{}
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanOutbox(rows)
}

func (s *Store) MarkSent(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE outbox SET status = 'sent', attempts = attempts + 1, sent_at = ?, last_error = '' WHERE id = ?`, now.Unix(), id)
	return err
}

func (s *Store) MarkRetry(ctx context.Context, id int64, next time.Time, errMsg string, final bool) error {
	status := "pending"
	if final {
		status = "failed"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE outbox SET status = ?, attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE id = ?`, status, next.Unix(), errMsg, id)
	return err
}

// Requeue puts a failed mail back into the queue (admin action).
func (s *Store) Requeue(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE outbox SET status = 'pending', attempts = 0, next_attempt_at = ? WHERE id = ? AND status = 'failed'`, time.Now().Unix(), id)
	return err
}

func (s *Store) CountSentSince(ctx context.Context, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at >= ?`, since.Unix()).Scan(&n)
	return n, err
}

// ---- maintenance ----

// Cleanup removes expired challenge nonces and sessions, and applies
// per-form retention to submissions (their outbox rows cascade).
func (s *Store) Cleanup(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM used_challenges WHERE expires_at < ?`, now.Unix()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now.Unix()); err != nil {
		return err
	}
	defs, err := s.ListForms(ctx)
	if err != nil {
		return err
	}
	for _, f := range defs {
		if f.Def.RetentionDays <= 0 {
			continue
		}
		cutoff := now.AddDate(0, 0, -f.Def.RetentionDays).Unix()
		if _, err := s.db.ExecContext(ctx, `DELETE FROM submissions WHERE form_id = ? AND created_at < ?`, f.Def.ID, cutoff); err != nil {
			return err
		}
	}
	// Keep one year of audit history.
	_, err = s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE ts < ?`, now.AddDate(-1, 0, 0).Unix())
	return err
}
