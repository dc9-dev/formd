// Command formd is a self-hosted form backend for static sites.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/dc9-dev/formd/internal/admin"
	"github.com/dc9-dev/formd/internal/antispam"
	"github.com/dc9-dev/formd/internal/config"
	"github.com/dc9-dev/formd/internal/forms"
	"github.com/dc9-dev/formd/internal/mail"
	"github.com/dc9-dev/formd/internal/server"
	"github.com/dc9-dev/formd/internal/store"
	"github.com/dc9-dev/formd/internal/worker"
)

var version = "dev"

const usage = `formd — backend formularzy dla stron statycznych

Użycie:
  formd [-env PLIK] <polecenie> [opcje]

Polecenia:
  serve                         uruchamia API formularzy i panel admina
  migrate                       tworzy/aktualizuje schemat bazy
  user add|passwd|del <login>   zarządza kontami panelu
  user list
  list   -form ID [-since 7d]   wypisuje zgłoszenia
  export -form ID [-format csv|json] [-since 30d]
  test-mail -to ADRES           wysyła wiadomość testową
  version
`

func main() {
	envFile := flag.String("env", ".env", "plik z konfiguracją")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if args[0] == "version" {
		fmt.Println(version)
		return
	}
	cfg, err := config.Load(*envFile)
	if err != nil {
		fatal(err)
	}
	log := newLogger(cfg.LogLevel)

	switch args[0] {
	case "serve":
		err = serve(cfg, log)
	case "migrate":
		var st *store.Store
		if st, err = store.Open(cfg.DBPath); err == nil {
			st.Close()
			fmt.Println("ok")
		}
	case "user":
		err = userCmd(cfg, args[1:])
	case "list":
		err = listCmd(cfg, args[1:])
	case "export":
		err = exportCmd(cfg, args[1:])
	case "test-mail":
		err = testMail(cfg, log, args[1:])
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "błąd:", err)
	os.Exit(1)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func serve(cfg *config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	key, err := st.SecretKey(ctx, "challenge_hmac_key", 32)
	if err != nil {
		return err
	}
	chal, err := antispam.NewChallenger(key)
	if err != nil {
		return err
	}
	reg := forms.NewRegistry()
	if err := admin.ReloadRegistry(ctx, st, reg, log); err != nil {
		return err
	}
	mailer, err := mail.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	w := worker.New(st, mailer, cfg.MailFrom, cfg.MailHourlyCap, log)
	go w.Run(ctx)

	limiter := antispam.NewLimiter(100_000)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				limiter.Sweep(now)
			}
		}
	}()

	pub := &server.Public{Cfg: cfg, Forms: reg, Store: st, Challenger: chal, Limiter: limiter, Wake: w.Wake, Log: log}
	servers := []*http.Server{newServer(cfg.ListenAddr, pub.Handler(), log)}

	if cfg.AdminEnabled() {
		adm, err := admin.New(cfg, st, reg, log)
		if err != nil {
			return err
		}
		servers = append(servers, newServer(cfg.AdminListenAddr, adm.Handler(), log))
		if n, _ := st.CountUsers(ctx); n == 0 {
			log.Warn("no admin users yet; create one with: formd user add <login>")
		}
	}

	errc := make(chan error, len(servers))
	for _, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			return err
		}
		log.Info("listening", "addr", s.Addr)
		go func(s *http.Server) {
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(s)
	}
	log.Info("formd started", "version", version, "mailer", cfg.Mailer, "admin", cfg.AdminListenAddr)

	select {
	case <-ctx.Done():
	case err := <-errc:
		log.Error("server error", "err", err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(shutdownCtx)
	}
	return nil
}

func newServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// ---- users ----

func userCmd(cfg *config.Config, args []string) error {
	if len(args) == 0 {
		return errors.New("użycie: formd user add|passwd|del <login> | formd user list")
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	if args[0] == "list" {
		users, err := st.ListUsers(ctx)
		if err != nil {
			return err
		}
		for _, u := range users {
			fmt.Printf("%s\tutworzony %s\thasło zmienione %s\n", u.Username, u.CreatedAt.Format(time.DateOnly), u.PasswordChangedAt.Format(time.DateOnly))
		}
		return nil
	}
	if len(args) != 2 {
		return errors.New("podaj login")
	}
	name := args[1]
	if len(name) == 0 || len(name) > 64 || strings.ContainsAny(name, " \t\r\n") {
		return errors.New("login: 1–64 znaki, bez spacji")
	}
	switch args[0] {
	case "add", "passwd":
		pw, err := readPassword()
		if err != nil {
			return err
		}
		hash, err := admin.HashPassword(pw)
		if err != nil {
			return err
		}
		if args[0] == "add" {
			if err := st.CreateUser(ctx, name, hash); err != nil {
				return err
			}
		} else if err := st.SetPassword(ctx, name, hash); err != nil {
			return err
		}
		st.Audit(ctx, name, "cli", "user_"+args[0], "")
		fmt.Println("ok")
	case "del":
		if err := st.DeleteUser(ctx, name); err != nil {
			return err
		}
		st.Audit(ctx, name, "cli", "user_del", "")
		fmt.Println("ok")
	default:
		return fmt.Errorf("nieznane polecenie user %q", args[0])
	}
	return nil
}

// readPassword prompts twice on a terminal, or reads one line from stdin
// (for automation: echo "$PW" | formd user add admin).
func readPassword() (string, error) {
	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Hasło: ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "Powtórz: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", errors.New("hasła nie są identyczne")
		}
		pw = string(a)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	return pw, admin.CheckPasswordPolicy(pw)
}

// ---- list / export ----

func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Unix(0, 0), nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil {
			return time.Time{}, fmt.Errorf("nieprawidłowe -since %q", s)
		}
		return time.Now().AddDate(0, 0, -n), nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("nieprawidłowe -since %q", s)
	}
	return time.Now().Add(-dur), nil
}

func loadSubs(cfg *config.Config, formID, since string) (forms.Definition, []store.Submission, error) {
	if formID == "" {
		return forms.Definition{}, nil, errors.New("podaj -form")
	}
	t, err := parseSince(since)
	if err != nil {
		return forms.Definition{}, nil, err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return forms.Definition{}, nil, err
	}
	defer st.Close()
	d, err := st.GetForm(context.Background(), formID)
	if err != nil {
		return d, nil, fmt.Errorf("formularz %q: %w", formID, err)
	}
	subs, err := st.ListSubmissions(context.Background(), formID, t, 1_000_000, 0)
	return d, subs, err
}

func listCmd(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	formID := fs.String("form", "", "identyfikator formularza")
	since := fs.String("since", "7d", "zakres, np. 7d, 12h")
	fs.Parse(args)
	d, subs, err := loadSubs(cfg, *formID, *since)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	head := []string{"CZAS", "IP"}
	for _, f := range d.Fields {
		head = append(head, strings.ToUpper(f.Name))
	}
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	for _, s := range subs {
		row := []string{s.CreatedAt.Format("2006-01-02 15:04"), s.IP}
		for _, f := range d.Fields {
			v := forms.CleanHeader(s.Data[f.Name], 40) // single line, control chars stripped
			row = append(row, v)
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

func exportCmd(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	formID := fs.String("form", "", "identyfikator formularza")
	format := fs.String("format", "csv", "csv albo json")
	since := fs.String("since", "", "zakres, np. 30d (domyślnie wszystko)")
	fs.Parse(args)
	d, subs, err := loadSubs(cfg, *formID, *since)
	if err != nil {
		return err
	}
	switch *format {
	case "csv":
		cw := csv.NewWriter(os.Stdout)
		if err := admin.WriteCSV(cw, d, subs); err != nil {
			return err
		}
		cw.Flush()
		return cw.Error()
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(subs)
	}
	return fmt.Errorf("nieznany format %q", *format)
}

func testMail(cfg *config.Config, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("test-mail", flag.ExitOnError)
	to := fs.String("to", "", "adres odbiorcy")
	fs.Parse(args)
	if _, err := forms.ParseEmail(*to); err != nil {
		return fmt.Errorf("-to: %w", err)
	}
	m, err := mail.New(context.Background(), cfg, log)
	if err != nil {
		return err
	}
	err = m.Send(context.Background(), mail.Message{
		From: cfg.MailFrom, To: *to, Subject: "formd: wiadomość testowa",
		Text: "Konfiguracja wysyłki formd działa.\n",
	})
	if err == nil {
		fmt.Println("wysłano")
	}
	return err
}
