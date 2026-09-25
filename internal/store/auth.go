package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type User struct {
	ID                int64
	Username          string
	PasswordHash      string
	CreatedAt         time.Time
	PasswordChangedAt time.Time
}

func (s *Store) CreateUser(ctx context.Context, username, hash string) error {
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(username, password_hash, created_at, password_changed_at) VALUES(?, ?, ?, ?) ON CONFLICT(username) DO NOTHING`, username, hash, now, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrExists
	}
	return nil
}

func (s *Store) UserByName(ctx context.Context, username string) (User, error) {
	var u User
	var c, p int64
	err := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at, password_changed_at FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &c, &p)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.CreatedAt, u.PasswordChangedAt = time.Unix(c, 0), time.Unix(p, 0)
	return u, err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, created_at, password_changed_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var c, p int64
		if err := rows.Scan(&u.ID, &u.Username, &c, &p); err != nil {
			return nil, err
		}
		u.CreatedAt, u.PasswordChangedAt = time.Unix(c, 0), time.Unix(p, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// SetPassword changes a password and revokes all of the user's sessions.
func (s *Store) SetPassword(ctx context.Context, username, hash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, username).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?`, hash, time.Now().Unix(), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- sessions ----

type Session struct {
	UserID    int64
	Username  string
	CSRF      string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// HashToken is how session tokens are stored: a leaked database does not
// yield usable cookies.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *Store) CreateSession(ctx context.Context, token string, userID int64, csrf, ip, ua string, expires time.Time) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, csrf, created_at, last_seen, expires_at, ip, user_agent) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		HashToken(token), userID, csrf, now, now, expires.Unix(), ip, ua)
	return err
}

// GetSession returns a live session, enforcing absolute expiry and idle timeout,
// and slides last_seen forward.
func (s *Store) GetSession(ctx context.Context, token string, idle time.Duration, now time.Time) (Session, error) {
	var ss Session
	var c, l, e int64
	err := s.db.QueryRowContext(ctx,
		`SELECT s.user_id, u.username, s.csrf, s.created_at, s.last_seen, s.expires_at
		 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`, HashToken(token)).
		Scan(&ss.UserID, &ss.Username, &ss.CSRF, &c, &l, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return ss, ErrNotFound
	}
	if err != nil {
		return ss, err
	}
	ss.CreatedAt, ss.LastSeen, ss.ExpiresAt = time.Unix(c, 0), time.Unix(l, 0), time.Unix(e, 0)
	if now.After(ss.ExpiresAt) || now.Sub(ss.LastSeen) > idle {
		s.DeleteSession(ctx, token)
		return ss, ErrNotFound
	}
	_, err = s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE token_hash = ?`, now.Unix(), HashToken(token))
	return ss, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, HashToken(token))
	return err
}

// ---- audit ----

type AuditEntry struct {
	TS       time.Time
	Username string
	IP       string
	Action   string
	Detail   string
}

func (s *Store) Audit(ctx context.Context, username, ip, action, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log(ts, username, ip, action, detail) VALUES(?, ?, ?, ?, ?)`, time.Now().Unix(), username, ip, action, detail)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, username, ip, action, detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var ts int64
		if err := rows.Scan(&ts, &a.Username, &a.IP, &a.Action, &a.Detail); err != nil {
			return nil, err
		}
		a.TS = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}
