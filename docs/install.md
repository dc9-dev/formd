# Deploy formd: instructions for an AI assistant

You are helping a person install formd, a self-hosted form backend for static sites (https://formd.top, source: https://github.com/dc9-dev/formd). formd is a single Go binary. It listens only on 127.0.0.1, the site's web server (nginx or Caddy) exposes its `/f/` path over HTTPS, and an admin panel on a separate local port is reached only through an SSH tunnel.

Work step by step on the person's Linux server. After each step, show what you ran and what it printed, and check the result before moving on.

## Rules

- **Ask before you change anything that already exists**: web server configuration, DNS, firewall, existing services. Show the diff first, then reload only after `nginx -t` (or `caddy validate`) passes.
- **Never expose the admin panel.** Port 8026 must stay on 127.0.0.1. Proxy only the `/f/` path to formd, never `/`.
- **Never handle the panel password.** The person types it in their own terminal (step 6). Do not ask for it, generate it in chat, or put it in a command line or a file.
- **Do not print secrets.** SMTP passwords and API keys go into `/etc/formd/formd.env` only (mode 0640, owner root, group formd). Do not echo them, do not commit them, do not paste them into logs.
- **Verify downloads** with `SHA256SUMS` before installing.
- If something fails, stop and explain; do not work around a security check (for example by binding to 0.0.0.0, disabling TLS or loosening the allowed origins).

## 0. Collect the facts

Ask the person, unless already given below:

1. The site's domain (for example `example.com`).
2. Where the site is hosted:
   - **same server**: formd will be at `https://example.com/f/`;
   - **elsewhere** (GitHub Pages, Netlify, Cloudflare Pages, S3): formd will run on a subdomain such as `https://forms.example.com/f/` on this server, which needs a DNS A (and AAAA, if used) record pointing to the server.
3. Web server on this machine: nginx or Caddy.
4. How mail should go out: SMTP (host, port, user, password, TLS mode), Amazon SES (region; IAM role or access keys), or `log` for a first test.
5. The address that should receive notifications, and the sender address (`MAIL_FROM`).
6. Panel and email language: English (`FORMD_LANG=en`, default) or Polish (`FORMD_LANG=pl`).

Then check the server: `uname -m` (x86_64 → `amd64`, aarch64 → `arm64`), `systemctl --version`, `nginx -v` or `caddy version`, and that you have sudo.

## 1. Download and verify

```sh
ARCH=amd64   # or arm64
cd /tmp
curl -LO https://github.com/dc9-dev/formd/releases/latest/download/formd-linux-$ARCH
curl -LO https://github.com/dc9-dev/formd/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Continue only if it prints `formd-linux-$ARCH: OK`. Note the version: `chmod +x formd-linux-$ARCH && ./formd-linux-$ARCH version`.

## 2. Install the service

Use the repository at the same version as the binary (replace `vX.Y.Z` with the version printed above):

```sh
git clone --depth 1 --branch vX.Y.Z https://github.com/dc9-dev/formd
cd formd
sudo sh deploy/install.sh /tmp/formd-linux-$ARCH
```

The script creates the system user `formd`, installs `/usr/local/bin/formd`, creates `/etc/formd/formd.env` (mode 0640) from `.env.example` with `DB_PATH=/var/lib/formd/formd.db`, and installs the hardened systemd unit `formd.service`. It does not start anything.

## 3. Configure

Edit `/etc/formd/formd.env` with sudo. Keep the network defaults:

```sh
LISTEN_ADDR=127.0.0.1:8025
ALLOWED_IPS=127.0.0.1,::1
TRUSTED_PROXIES=127.0.0.1,::1
ADMIN_LISTEN_ADDR=127.0.0.1:8026
```

Set:

```sh
FORMD_LANG=en                                # or pl
MAIL_FROM="Website <no-reply@example.com>"   # a sender your mail service may send as
```

And one mail option:

```sh
# SMTP
MAILER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=...
SMTP_PASS=...          # the person enters it; do not print it
SMTP_TLS=starttls      # starttls | tls

# or Amazon SES
MAILER=ses
AWS_REGION=eu-central-1   # credentials from the instance IAM role, or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY

# or no mail yet
MAILER=log             # emails only go to: journalctl -u formd
```

Optional content checks with a language model are described in the README (section "Content scoring"); skip them on a first install.

## 4. Start

```sh
sudo systemctl enable --now formd
systemctl status formd --no-pager
curl -s http://127.0.0.1:8025/healthz
```

If it does not start, read `journalctl -u formd -n 50 --no-pager`; formd explains configuration errors on startup.

## 5. Expose /f/ over HTTPS

Start from the example that matches the setup, from the cloned repository:

- same server, nginx: `deploy/nginx-same-domain.conf`
- separate subdomain, nginx: `deploy/nginx-subdomain.conf`
- Caddy, either case: `deploy/Caddyfile` (pick one variant)

Merge only the `location /f/ { ... }` block (or Caddy's `handle /f/*`) into the existing site configuration; for a subdomain, create a new server block. The proxy must pass `X-Real-IP` and limit the body to 64 KB, as in the examples. For nginx, get a certificate with `sudo certbot --nginx -d <host>` if the host has none. Show the person the diff, test the configuration, then reload.

## 6. Create the panel account (the person does this)

Ask the person to run this in their own terminal on the server and choose a password of at least 12 characters:

```sh
sudo -u formd formd -env /etc/formd/formd.env user add admin
```

## 7. Create the form in the panel (the person does this)

On their own computer:

```sh
ssh -L 8026:127.0.0.1:8026 <user>@<server>
```

Then open http://localhost:8026, log in, click **New form**, use the ID `contact` and the site's origin (for example `https://example.com`). In the form settings, add the notification address, turn the form on and save. The **HTML code** tab has the code for the page.

## 8. Add the form to the site

Same server: post to `/f/contact`. Subdomain: use the full address `https://forms.example.com/f/contact`, also in the script `src`.

```html
<form action="/f/contact" method="post" data-formd="ajax">
  <input name="name" required>
  <input type="email" name="email" required>
  <textarea name="message" required></textarea>
  <div style="position:absolute;left:-10000px" aria-hidden="true">
    <input name="website" tabindex="-1" autocomplete="off">
  </div>
  <button>Send</button>
  <p data-formd-status role="status"></p>
</form>
<script src="/f/formd.js" defer></script>
```

Messages to visitors follow the page's `<html lang>` (English, or Polish for `pl`). If the site sends a Content-Security-Policy and formd is on a subdomain, add that origin to `script-src`, `connect-src` and `form-action`.

## 9. Verify from outside

```sh
curl -I https://<host>/f/formd.js                 # expect 200
curl -s https://<host>/f/contact/challenge        # expect {"bits":16,"min_seconds":3,"token":"..."}
curl -s -o /dev/null -w "%{http_code}\n" https://<host>/   # subdomain setup: expect 404, never the panel
```

Then ask the person to send the form from the live site and confirm the submission appears in the panel and the email arrives (with `MAILER=log`, in `journalctl -u formd`).

## Done

Summarise for the person: where formd runs, which files you changed, how to open the panel (the SSH tunnel), and how to update later (download the new binary, verify, `sudo install -m 0755 formd-linux-$ARCH /usr/local/bin/formd`, `sudo systemctl restart formd`). Recommend a daily backup of `/var/lib/formd/formd.db`.
