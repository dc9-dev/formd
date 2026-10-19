![formd — Static forms backend](assets/github/formd-github-banner-white.png)

# formd

[![CI](https://github.com/dc9-dev/formd/actions/workflows/ci.yml/badge.svg)](https://github.com/dc9-dev/formd/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/dc9-dev/formd)](https://github.com/dc9-dev/formd/releases/latest) [![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

**English** · [Polski](README.pl.md)

**A self-hosted form backend for static sites.** A single Go binary that you install on the same server as your site. It accepts form submissions, validates them, stores them in SQLite, and sends a notification to the site owner and a confirmation to the sender (SMTP, Amazon SES, or log only). No external SaaS, no third-party captcha, and no data leaving your server.

Project site: **https://formd.top/**. It has a live demo where you can submit a form or send a bot and see which check stops it. It also has a step-by-step installation guide tailored to your domain.

```
browser ──POST /f/kontakt──▶ nginx/Caddy (TLS) ──▶ 127.0.0.1:8025  formd (API)
                                                   127.0.0.1:8026  formd (panel, over an SSH tunnel)
                                                         │
                                                  SQLite + mail queue ──▶ SMTP / SES
```

## What it does

- **Forms API** `POST /f/{id}`: urlencoded, multipart (no files) and JSON. Without JS you get a 303 redirect; with `fetch` you get a JSON response.
- **Admin panel**: create and configure forms (fields, origins, recipients, email templates, limits), browse and export submissions (CSV), a mail queue with retries, and an event log.
- **Mail queue (outbox)**: a submission and its emails are saved in a single transaction, so an SMTP outage does not lose messages. Failed sends are retried with backoff (1 min → 24 h).
- **Retention**: submissions older than N days are deleted automatically (GDPR).

![formd panel: list of submissions for a form](docs/assets/panel-submissions.webp)

## How it compares

formd is for people who already have, or are happy to run, a small Linux server. If you have no server at all, a hosted form service is simpler.

| | formd | Formspree, Basin and similar | Netlify Forms | Formbricks |
| --- | --- | --- | --- | --- |
| Where it runs | your server, one binary | the provider's cloud | Netlify, for sites hosted there | your server or their cloud |
| Where submissions are stored | SQLite on your server | with the provider | with Netlify | your database or their cloud |
| Works with any static host | yes | yes | Netlify only | yes |
| Cost | free (AGPL-3.0) | plans with submission limits | included with Netlify plans, with limits | free self-hosted, paid cloud |
| Focus | contact and feedback forms for static sites | forms | forms | surveys and experience management |

## Security

| Layer | Mechanism |
| --- | --- |
| Network | Listens only on a specific IP (`0.0.0.0` is rejected at startup). A connection IP allowlist is checked before routing. `X-Forwarded-For` / `X-Real-IP` headers are honoured only from trusted proxies. |
| Panel | Separate port, never proxied. IP allowlist plus a `Host` header allowlist (protection against DNS rebinding). Passwords hashed with argon2id. Server-side sessions; the database stores only a hash of the token. `HttpOnly` + `SameSite=Strict` + `Secure` cookie. Per-session CSRF token plus `Origin`/`Sec-Fetch-Site` checks. Strict CSP, no JavaScript. Login attempt limits per IP and per username. Audit log. |
| Input | Fields not in the form definition are rejected. Length is counted in characters. Control characters, bidi characters and newlines are rejected in single-line fields. Email addresses without a display name. Request body size limit. No file uploads. |
| Email | Headers are built from validated addresses; CR/LF in a header causes an error (no header injection). The subject is reduced to a single line. HTML templates are escaped automatically (`html/template`). STARTTLS is required, with no silent downgrade. |
| Export | CSV neutralises formula injection (`=`, `+`, `-`, `@`). |
| Process | systemd unit with full hardening (`ProtectSystem=strict`, syscall filter, no capabilities). Database and directory with 0600/0700 permissions. |

### Protection against mass submissions

Each form has its own settings in the panel:

1. **Signed challenge + proof-of-work.** `formd.js` fetches an HMAC-signed token and, before submitting, solves a SHA-256 puzzle of a given difficulty (16 bits by default: a fraction of a second for a human, expensive across thousands of submissions). The token is single-use, bound to the form, and valid for 2 h. No external captcha needed.
2. **Minimum fill-in time**, measured on the server from the moment the token was issued.
3. **Rate limits:** per IP and form, per IP globally, for issuing challenges, an hourly cap on accepted submissions per form, and a global cap on emails per hour.
4. **Confirmations:** a daily limit of emails to a single address, so nobody can turn your server into a mail-bombing tool.
5. **Content filters:** honeypot, maximum number of links, a list of blocked phrases, duplicate rejection.
6. **Silent rejection:** spam and duplicates get a fake success response, so a bot cannot tell which filter caught it.
7. **fail2ban-friendly logs:** a ready-made filter in `deploy/fail2ban-filter.conf`.
8. **Content scoring with Jev** (optional), described below.

## Content scoring (Jev)

Optionally, formd can score message content with the [Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev) model (TypeSafe) via OpenRouter, or with a Polish model on your own hardware ([see below](#polish-model-on-your-own-hardware-basal)). Jev does not generate text; it returns calibrated probabilities for predefined questions. For each submission formd asks about:

| Question | Type | Result |
| --- | --- | --- |
| Purpose of the message | `choice` | question / order or quote / complaint / feedback / other |
| Spam (advertising, SEO, mass mailing, content unrelated to the site) | `noul` | probability 0–100% |
| Fraud / phishing | `noul` | probability 0–100% |
| Abusive content | `noul` | probability 0–100% |
| Urgency | `score` | 1–5 |

**Risk** = max(spam, fraud, abusive). When it exceeds the threshold set in the panel (70% by default), formd does what you chose for the form:

- **Hold** (default): the submission is saved, but its emails (including the confirmation to the sender) wait until you approve them in the panel under the *Wstrzymane* (Held) tab.
- **Flag**: emails go out as usual, with a `[SPAM?]` prefix in the subject.
- **Drop**: the submission is silently discarded, like other spam.

The score for each submission is shown in the panel and appended to the notification email.

**Security and cost:**

- Jev is queried **only after all the cheap filters** (challenge, limits, honeypot, duplicates), so bots rejected earlier cost nothing.
- The questions are fixed, in English, and hard-coded. User content goes only into `state`, inside fenced blocks, with a note that it is untrusted data. Even so, the text may try to steer the score, which is why the default action is *hold* rather than the irreversible *drop*.
- **Privacy:** field contents are sent to OpenRouter and TypeSafe. Email addresses are replaced with just their domain. The feature is off until you set a key and enable it for a specific form. Mention this in your site's privacy policy.
- Daily budget (`JEV_DAILY_BUDGET_USD`), timeout (`JEV_TIMEOUT`, 4 s by default) and a cost counter on the panel's home page. One submission costs about 0.00002 USD.
- If Jev does not respond or the budget runs out, the submission goes through without a score (fail-open). In the form settings you can choose to hold such submissions instead.
- The API key is sent only over HTTPS and never ends up in logs or error messages.

Configuration in `.env`:

```sh
OPENROUTER_API_KEY=sk-or-...      # https://openrouter.ai/settings/keys (set a credit limit)
JEV_MODEL=jev-1.13
JEV_TIMEOUT=4s
JEV_DAILY_BUDGET_USD=1
```

Then in the panel: form → **Ocena treści (Jev)** (content scoring) → enable it, choose the action and threshold, and add one sentence describing what the site is about (this improves accuracy).

### Polish model on your own hardware (basal)

Instead of Jev on OpenRouter, formd can use the open **basal** models by [Remek](https://huggingface.co/Remek), trained for decisions in Polish and English. They run on your own machine with the [basal](https://github.com/rkinas/basal) engine (Apache-2.0), which serves the same System One API as Jev, so formd asks them the same questions. Field contents never leave your infrastructure and there is no per-request cost.

| Model | Built on | Runs on |
| --- | --- | --- |
| [`Remek/basal-omni-1.0-ultra`](https://huggingface.co/Remek/basal-omni-1.0-ultra) (31B, formd's default) | Gemma 4 | NVIDIA GPU; BF16 weights need about 62 GB of GPU memory (an 80 GB card) |
| [`Remek/basal-2.0-4.5B`](https://huggingface.co/Remek/basal-2.0-4.5B) | Bielik v3 (Polish) | a smaller NVIDIA GPU, a Mac with Apple Silicon (`-MLX-8bit`) or a CPU through Ollama (`-GGUF`) |

**1. Install the engine.** On an NVIDIA machine, in a fresh Python environment (from the basal install guide; check [docs/INSTALL.md](https://github.com/rkinas/basal/blob/main/docs/INSTALL.md) for the current version and for Mac, Ollama and llama.cpp):

```sh
uv venv --python 3.12 ~/basal-env && source ~/basal-env/bin/activate
uv pip install torch==2.11.0 --index-url https://download.pytorch.org/whl/cu128
uv pip install "basal[fp8] @ https://github.com/rkinas/basal/archive/refs/tags/v2.2.0.tar.gz"
```

**2. Start it, on localhost only** (basal-serve has no authentication):

```sh
# the 31B model
basal-serve --model Remek/basal-omni-1.0-ultra --mode eager --host 127.0.0.1 --port 8000

# or the smaller Bielik-based model
basal-serve --model Remek/basal-2.0-4.5B --mode fast --template-prefix off --host 127.0.0.1 --port 8000
```

The first start downloads the weights from Hugging Face. Run it as a service (for example a systemd unit) so it comes back after a reboot.

**3. Check that it answers:**

```sh
curl -s http://127.0.0.1:8000/v1/systemone -H 'content-type: application/json' -d '{
  "state": "Cheapest SEO links, buy now!",
  "questions": {"spam": {"type": "noul", "instructions": "Is this message spam?"}}}'
# {"model": "...", "answers": {"spam": {"type": "noul", "noul": 0.9..., ...}}, ...}
```

**4. Point formd at it** in `/etc/formd/formd.env` and restart formd:

```sh
JEV_PROVIDER=basal
# defaults: JEV_URL=http://127.0.0.1:8000/v1/systemone, JEV_MODEL=Remek/basal-omni-1.0-ultra
# for another model, use the same name you passed to --model:
#JEV_MODEL=Remek/basal-2.0-4.5B
# on a CPU, allow more time (at most 15s; it delays form submission):
#JEV_TIMEOUT=10s
```

The startup log shows `jev content assessment available provider=basal`. Then enable **Ocena treści (Jev)** (content scoring) for a form in the panel. The form settings now say which model scores submissions and that their content stays on the server.

**Notes:**

- formd accepts plain `http` only for a local address. If the model runs on another machine, put an HTTPS gateway in front of it and set `JEV_URL=https://…`. If the gateway needs a token, set `BASAL_API_KEY` (sent as `Authorization: Bearer`). `OPENROUTER_API_KEY` is never sent to a basal endpoint.
- The cost counter and daily budget do not apply; the panel hides the cost tile. Holding, flagging, thresholds and fail-open work the same as with Jev.
- formd's integration is tested against the API format documented by basal, not against a real GPU deployment. If something does not match, the submission goes through without a score and the panel shows the error.

## Quick start

```sh
make build                       # or: go install github.com/dc9-dev/formd/cmd/formd@latest
cp .env.example .env             # set MAILER=log to start with
./formd user add admin           # panel account (password of at least 12 characters)
./formd serve
```

Panel: `http://localhost:8026`. Create a form, enter the site's origin, the fields and the recipients, then enable it. Ready-to-use HTML is in the **Kod HTML** (HTML code) tab, and there is an example in [`examples/contact.html`](examples/contact.html).

```html
<form action="/f/kontakt" method="post" data-formd="ajax"
      data-formd-success="Thank you! Your message has been sent."
      data-formd-error="The form could not be sent."
      data-formd-server-errors="off">
  <input name="name" required>
  <input type="email" name="email" required>
  <textarea name="message" required></textarea>
  <div style="position:absolute;left:-10000px" aria-hidden="true"><input name="website" tabindex="-1" autocomplete="off"></div>
  <button>Send</button>
  <p data-formd-status role="status"></p>
</form>
<script src="/f/formd.js" defer></script>
```

The messages built into `formd.js` and the per-field validation messages from the server are in Polish. The `data-formd-*` attributes above set English success and error messages, and `data-formd-server-errors="off"` shows `data-formd-error` instead of the server's messages. The "sending" and network error messages can be set too; see [Messages in other languages](#messages-in-other-languages).

> The relative URL `/f/kontakt` works when formd is exposed through a reverse proxy **on the same domain as the site**. With a separate subdomain, use full `https://…` URLs. See [HTTPS and reverse proxy](#https-and-reverse-proxy).

## Deploying to a server

```sh
make dist                                     # dist/formd-linux-amd64, -arm64
scp dist/formd-linux-amd64 serwer:/tmp/formd
sudo ./deploy/install.sh /tmp/formd           # formd user, /etc/formd, systemd
sudo systemctl enable --now formd
sudo -u formd formd -env /etc/formd/formd.env user add admin
```

- Panel from your own computer: `ssh -L 8026:127.0.0.1:8026 serwer`, then `http://localhost:8026`.
- Forms are exposed through a reverse proxy with HTTPS, as described below.

## HTTPS and reverse proxy

formd **does not handle TLS and should not be reachable from the internet**. It listens only on `127.0.0.1`. Encryption is provided by a reverse proxy (nginx or Caddy), which accepts the HTTPS connection from the browser and forwards only the `/f/` path to formd.

This is a requirement, not an option: a page served over HTTPS **cannot** submit a form to an `http://` URL. The browser blocks `fetch` as *mixed content*, and a plain form POST either shows an insecure form warning or is blocked. The URL in `action` must therefore be an HTTPS URL served by your proxy.

```
browser ──HTTPS──▶ nginx / Caddy :443 (certificate) ──HTTP──▶ 127.0.0.1:8025 formd
                   └─ /f/* only                               (local traffic, off the network)
```

### Which option?

| | A. Same domain (recommended) | B. Separate subdomain |
| --- | --- | --- |
| When | The static site is on the same server as formd | The site is hosted elsewhere: GitHub Pages, Netlify, S3/CloudFront, another server |
| Form `action` | `/f/kontakt` | `https://forms.example.com/f/kontakt` |
| Script | `/f/formd.js` | `https://forms.example.com/f/formd.js` |
| Certificate | same as the site | separate one for `forms.example.com` |
| CORS | not involved | formd responds with CORS headers for the origins set in the panel |
| Configuration | [`deploy/nginx-same-domain.conf`](deploy/nginx-same-domain.conf), [`deploy/Caddyfile`](deploy/Caddyfile) | [`deploy/nginx-subdomain.conf`](deploy/nginx-subdomain.conf), [`deploy/Caddyfile`](deploy/Caddyfile) |

In both options, **the allowed origin in the panel is the site's address** (e.g. `https://example.com`), not formd's address.

### Step by step (nginx + Let's Encrypt)

```sh
# 1. (option B) DNS record: forms.example.com -> server IP
# 2. configuration
sudo cp deploy/nginx-same-domain.conf /etc/nginx/conf.d/example.com.conf   # or nginx-subdomain.conf
sudo nano /etc/nginx/conf.d/example.com.conf                               # replace example.com
# 3. certificate (certbot fills in the paths and handles renewal)
sudo certbot --nginx -d example.com -d www.example.com                      # B: -d forms.example.com
sudo nginx -t && sudo systemctl reload nginx
```

Caddy does step 3 automatically: all you need is [`deploy/Caddyfile`](deploy/Caddyfile) with your domain and `systemctl reload caddy`.

Settings in `/etc/formd/formd.env` for a proxy on the same host:

```sh
LISTEN_ADDR=127.0.0.1:8025
ALLOWED_IPS=127.0.0.1,::1        # only the proxy can connect to formd
TRUSTED_PROXIES=127.0.0.1,::1    # X-Real-IP is trusted only from the proxy (per-IP limits)
```

If the proxy runs on a **different machine** from formd, set `LISTEN_ADDR` to that machine's private address (e.g. `10.0.0.5:8025`) and put the proxy's address in `ALLOWED_IPS` and `TRUSTED_PROXIES`. Traffic between them should go over a private network or a VPN (WireGuard), never over the internet.

### Messages in other languages

The default `formd.js` messages are in Polish. For sites in other languages, set them with form attributes:

```html
<form action="/f/kontakt" method="post" data-formd="ajax"
      data-formd-sending="Sending…"
      data-formd-success="Thank you! Your message has been sent."
      data-formd-error="Your message could not be sent. Please email us."
      data-formd-network-error="Could not send the form. Please try again."
      data-formd-server-errors="off">
```

`data-formd-server-errors="off"` hides the detailed validation messages from the server (they are in Polish) and shows `data-formd-error` instead.

### Option B: site on another host

```html
<form action="https://forms.example.com/f/kontakt" method="post" data-formd="ajax">
  …
</form>
<script src="https://forms.example.com/f/formd.js" defer></script>
```

If the site has its own Content-Security-Policy, add `https://forms.example.com` to `script-src`, `connect-src` and `form-action`.

### Checking the setup

```sh
curl -I https://example.com/f/formd.js                # 200, text/javascript
curl -s https://example.com/f/kontakt/challenge \
     -H 'Origin: https://example.com'                  # {"token":"…","bits":16,…}
curl -s -o /dev/null -w '%{http_code}\n' \
     https://example.com/f/kontakt/challenge \
     -H 'Origin: https://evil.example'                 # 403, foreign origin
curl -s -o /dev/null -w '%{http_code}\n' http://example.com/f/formd.js   # 301 -> HTTPS
curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 http://IP_SERWERA:8025/healthz   # no connection: formd not visible from outside
curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 http://IP_SERWERA:8026/login     # no connection: panel not visible from outside
```

In the browser: DevTools → Network → submitting the form should show `POST https://…/f/kontakt` with status 200 (ajax mode) or 303 (plain POST), and no *mixed content* warnings in the console.

## Email delivery

| `MAILER` | Requires |
| --- | --- |
| `smtp` | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_TLS=starttls\|tls\|none`. Works with SES SMTP, Postfix, Mailgun, etc. |
| `ses` | `AWS_REGION` + standard AWS credentials (environment variables or an instance IAM role). Sends through the SES API v2. |
| `log` | Nothing. Emails only go to the logs (for testing). |

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

## Development

```sh
make test     # go test -race ./...
make vet
```

Layout: `cmd/formd` (CLI), `internal/server` (public API + `formd.js`), `internal/admin` (panel), `internal/antispam` (challenge, PoW, limits), `internal/forms` (definitions and validation), `internal/store` (SQLite), `internal/mail` (SMTP/SES/log), `internal/worker` (queue).

## FAQ

**How do I add a contact form to a static site without a SaaS?**
Install formd on a Linux server, proxy `/f/` through nginx or Caddy over HTTPS, create the form in the panel and paste the HTML from [Quick start](#quick-start). The [website](https://formd.top/#install) has a step-by-step guide that fills in your domain.

**Does it work with GitHub Pages, Netlify, Cloudflare Pages or S3?**
Yes. The site stays where it is; formd runs on a subdomain such as `forms.example.com` on a server you control. See [Option B](#option-b-site-on-another-host).

**How does it stop spam without a captcha?**
A signed single-use token with a SHA-256 proof-of-work, then origin, rate limit, minimum fill time, honeypot and duplicate checks on the server. Optionally a language model scores the content. See [Protection against mass submissions](#protection-against-mass-submissions).

**Where are submissions stored?**
In SQLite on your server. Read them in the panel, export CSV, or run `formd export`.

**What does it need?**
A Linux server (x86-64 or ARM64), a domain, nginx or Caddy, and SMTP or Amazon SES.

## License

Copyright (C) 2026 Łukasz Sobiecki

formd is free software licensed under the [GNU Affero General Public License v3.0](LICENSE). You can use, modify and distribute it under its terms. If you make a modified version available to others over a network, you must also make its source code available to them.

If the AGPL terms do not suit you, for example because you want to build formd into a closed product, ask about a commercial license by [opening an issue on GitHub](https://github.com/dc9-dev/formd/issues).
