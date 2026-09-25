![formd — Static forms backend](assets/github/formd-github-banner.png)

# formd

**Samodzielny backend formularzy dla stron statycznych.** Jedna binarka w Go, którą instalujesz na tym samym serwerze co stronę. Przyjmuje formularz, waliduje go, zapisuje do SQLite i wysyła powiadomienie do właściciela oraz potwierdzenie do nadawcy (SMTP, Amazon SES albo tylko log). Bez zewnętrznych SaaS-ów, bez captchy od firm trzecich, bez wysyłania danych poza serwer.

Strona projektu: **https://dc9-dev.github.io/formd/**

```
przeglądarka ──POST /f/kontakt──▶ nginx/Caddy (TLS) ──▶ 127.0.0.1:8025  formd (API)
                                                         127.0.0.1:8026  formd (panel, przez tunel SSH)
                                                               │
                                                        SQLite + kolejka maili ──▶ SMTP / SES
```

## Co robi

- **API formularzy** `POST /f/{id}`: urlencoded, multipart (bez plików) i JSON. Bez JS działa przekierowanie 303, a przy `fetch` odpowiedź w JSON.
- **Panel admina**: tworzenie i konfiguracja formularzy (pola, originy, odbiorcy, szablony maili, limity), przegląd i eksport zgłoszeń (CSV), kolejka maili z ponawianiem, dziennik zdarzeń.
- **Kolejka maili (outbox)**: zgłoszenie i maile zapisują się w jednej transakcji, więc awaria SMTP nie gubi wiadomości. Nieudane wysyłki są ponawiane z backoffem (1 min → 24 h).
- **Retencja**: zgłoszenia starsze niż N dni są automatycznie usuwane (RODO).

## Bezpieczeństwo

| Warstwa | Mechanizm |
| --- | --- |
| Sieć | Nasłuch tylko na konkretnym IP (`0.0.0.0` jest odrzucane przy starcie). Allowlista IP połączeń sprawdzana przed routingiem. Nagłówki `X-Forwarded-For` / `X-Real-IP` honorowane wyłącznie od zaufanych proxy. |
| Panel | Osobny port, nigdy nie proxowany. Allowlista IP + allowlista nagłówka `Host` (ochrona przed DNS rebinding). Hasła w argon2id. Sesje po stronie serwera, w bazie tylko hash tokenu. Cookie `HttpOnly` + `SameSite=Strict` + `Secure`. Token CSRF per sesja + sprawdzanie `Origin`/`Sec-Fetch-Site`. Ścisły CSP, bez JavaScriptu. Limit prób logowania per IP i per login. Dziennik audytowy. |
| Dane wejściowe | Pola spoza definicji są odrzucane. Długość liczona w znakach. Zakaz znaków sterujących, bidi i nowych linii w polach jednowierszowych. Adres e-mail bez nazwy wyświetlanej. Limit rozmiaru body. Brak uploadu plików. |
| Maile | Nagłówki budowane z walidowanych adresów, CR/LF w nagłówku kończy się błędem (brak header injection). Temat czyszczony do jednej linii. Szablony HTML escapowane automatycznie (`html/template`). STARTTLS wymagany, bez cichego downgrade'u. |
| Eksport | CSV neutralizuje formula injection (`=`, `+`, `-`, `@`). |
| Proces | Jednostka systemd z pełnym utwardzeniem (`ProtectSystem=strict`, filtr syscalli, brak capabilities). Baza i katalog z prawami 0600/0700. |

### Ochrona przed masową wysyłką

Każdy formularz ma własne ustawienia w panelu:

1. **Podpisany challenge + proof-of-work.** `formd.js` pobiera token podpisany HMAC i przed wysłaniem rozwiązuje zadanie SHA-256 o zadanej trudności (domyślnie 16 bitów, ułamek sekundy dla człowieka, kosztowne przy tysiącach zgłoszeń). Token jest jednorazowy, powiązany z formularzem i ważny 2 h. Nie trzeba zewnętrznej captchy.
2. **Minimalny czas wypełnienia** liczony po stronie serwera od wydania tokenu.
3. **Limity tempa:** per IP i formularz, per IP globalnie, dla wydawania challenge'y, godzinowy limit przyjęć na formularz oraz globalny limit maili na godzinę.
4. **Potwierdzenia:** limit maili na jeden adres na dobę, żeby nikt nie zrobił z Twojego serwera narzędzia do mail-bombingu.
5. **Filtry treści:** honeypot, maksymalna liczba linków, lista zablokowanych fraz, odrzucanie duplikatów.
6. **Ciche odrzucanie:** spam i duplikaty dostają udawany sukces, więc bot nie wie, który filtr go złapał.
7. **Logi pod fail2ban:** gotowy filtr w `deploy/fail2ban-filter.conf`.

## Szybki start

```sh
make build                       # lub: go install github.com/dc9-dev/formd/cmd/formd@latest
cp .env.example .env             # ustaw MAILER=log na początek
./formd user add admin           # konto do panelu (min. 12 znaków hasła)
./formd serve
```

Panel: `http://localhost:8026`. Utwórz formularz, podaj origin strony, pola i odbiorców, a potem włącz go. Gotowy kod HTML znajdziesz w zakładce **Kod HTML**, a przykład w [`examples/contact.html`](examples/contact.html).

```html
<form action="/f/kontakt" method="post" data-formd="ajax">
  <input name="name" required>
  <input type="email" name="email" required>
  <textarea name="message" required></textarea>
  <div style="position:absolute;left:-10000px" aria-hidden="true"><input name="website" tabindex="-1" autocomplete="off"></div>
  <button>Wyślij</button>
  <p data-formd-status role="status"></p>
</form>
<script src="/f/formd.js" defer></script>
```

## Wdrożenie na serwerze

```sh
make dist                                     # dist/formd-linux-amd64, -arm64
scp dist/formd-linux-amd64 serwer:/tmp/formd
sudo ./deploy/install.sh /tmp/formd           # użytkownik formd, /etc/formd, systemd
sudo systemctl enable --now formd
sudo -u formd formd -env /etc/formd/formd.env user add admin
```

- Reverse proxy: [`deploy/nginx.conf`](deploy/nginx.conf) lub [`deploy/Caddyfile`](deploy/Caddyfile). Wystawiaj **tylko** `/f/`.
- Panel z własnego komputera: `ssh -L 8026:127.0.0.1:8026 serwer`, potem `http://localhost:8026`.

## Konfiguracja wysyłki

| `MAILER` | Wymaga |
| --- | --- |
| `smtp` | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_TLS=starttls\|tls\|none`. Działa z SES SMTP, Postfixem, Mailgunem itd. |
| `ses` | `AWS_REGION` + standardowe poświadczenia AWS (zmienne środowiskowe lub rola IAM instancji). Wysyłka przez SES API v2. |
| `log` | Nic. Maile trafiają tylko do logów (do testów). |

Test: `formd test-mail -to ty@example.com`.

## CLI

```
formd serve
formd migrate
formd user add|passwd|del <login> · formd user list
formd list   -form kontakt -since 7d
formd export -form kontakt -format csv|json [-since 30d]
formd test-mail -to adres@example.com
```

## Rozwój

```sh
make test     # go test -race ./...
make vet
```

Struktura: `cmd/formd` (CLI), `internal/server` (publiczne API + `formd.js`), `internal/admin` (panel), `internal/antispam` (challenge, PoW, limity), `internal/forms` (definicje i walidacja), `internal/store` (SQLite), `internal/mail` (SMTP/SES/log), `internal/worker` (kolejka).
