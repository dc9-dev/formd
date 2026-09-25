// Package store persists forms, submissions, the mail outbox, admin users,
// sessions and the audit log in SQLite. All queries are parameterised.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct{ db *sql.DB }

// Open opens (creating if needed) the database file with restrictive
// permissions and applies migrations.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	// Create the file up front so it never exists with a permissive umask.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()

	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "secure_delete(1)")
	q.Add("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// A single connection serialises writers; traffic is small and this
	// removes SQLITE_BUSY races entirely.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

var migrations = []string{
	`CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value BLOB NOT NULL
	);
	CREATE TABLE forms (
		id         TEXT PRIMARY KEY,
		definition TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE submissions (
		id           TEXT PRIMARY KEY,
		form_id      TEXT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
		data         TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		ip           TEXT NOT NULL,
		user_agent   TEXT NOT NULL,
		created_at   INTEGER NOT NULL
	);
	CREATE INDEX submissions_form_time ON submissions(form_id, created_at);
	CREATE INDEX submissions_form_hash ON submissions(form_id, content_hash, created_at);
	CREATE TABLE outbox (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		submission_id   TEXT REFERENCES submissions(id) ON DELETE CASCADE,
		form_id         TEXT NOT NULL,
		kind            TEXT NOT NULL,
		to_addr         TEXT NOT NULL,
		reply_to        TEXT NOT NULL DEFAULT '',
		subject         TEXT NOT NULL,
		body_text       TEXT NOT NULL,
		body_html       TEXT NOT NULL DEFAULT '',
		status          TEXT NOT NULL DEFAULT 'pending',
		attempts        INTEGER NOT NULL DEFAULT 0,
		next_attempt_at INTEGER NOT NULL,
		last_error      TEXT NOT NULL DEFAULT '',
		created_at      INTEGER NOT NULL,
		sent_at         INTEGER
	);
	CREATE INDEX outbox_due ON outbox(status, next_attempt_at);
	CREATE INDEX outbox_recipient ON outbox(kind, to_addr, created_at);
	CREATE INDEX outbox_sent ON outbox(sent_at);
	CREATE TABLE used_challenges (
		nonce      TEXT PRIMARY KEY,
		expires_at INTEGER NOT NULL
	);
	CREATE TABLE users (
		id                  INTEGER PRIMARY KEY AUTOINCREMENT,
		username            TEXT NOT NULL UNIQUE,
		password_hash       TEXT NOT NULL,
		created_at          INTEGER NOT NULL,
		password_changed_at INTEGER NOT NULL
	);
	CREATE TABLE sessions (
		token_hash TEXT PRIMARY KEY,
		user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		csrf       TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		last_seen  INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		ip         TEXT NOT NULL,
		user_agent TEXT NOT NULL
	);
	CREATE TABLE audit_log (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		ts       INTEGER NOT NULL,
		username TEXT NOT NULL,
		ip       TEXT NOT NULL,
		action   TEXT NOT NULL,
		detail   TEXT NOT NULL
	);
	CREATE INDEX audit_ts ON audit_log(ts);`,
}

func (s *Store) migrate(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// SecretKey returns a persistent random key, generating it on first use.
func (s *Store) SecretKey(ctx context.Context, name string, size int) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, name).Scan(&v)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	v = make([]byte, size)
	if _, err := rand.Read(v); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING`, name, v); err != nil {
		return nil, err
	}
	return s.SecretKey(ctx, name, size)
}

// NewID returns a random 128-bit hex identifier.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
