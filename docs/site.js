/* formd.top — a live walk-through of one submission. The proof-of-work is
   real (same SHA-256 search as formd.js); the server checks are simulated
   with formd's own rules: 5 submissions per IP in 10 minutes, at least
   3 seconds after the token, empty honeypot, no duplicate content.
   Everything is written with textContent and stays in the browser. */
(function () {
  'use strict';

  // The page language picks the strings; the same script serves / and /pl/.
  var EN = document.documentElement.lang !== 'pl';
  function t(en, pl) { return EN ? en : pl; }

  // Remember an explicit language choice so / does not send a Polish
  // browser back to /pl/ after the visitor picked English.
  document.querySelectorAll('[data-lang]').forEach(function (a) {
    a.addEventListener('click', function () { try { localStorage.setItem('formd-lang', a.getAttribute('data-lang')); } catch (e) {} });
  });

  // ---- SHA-256 (first word only), same algorithm as formd.js ----
  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);
  var W = new Uint32Array(64);
  function sha256First(bytes, len) {
    var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    var total = ((len + 9 + 63) >> 6) << 6, buf = new Uint8Array(total);
    buf.set(bytes.subarray(0, len)); buf[len] = 0x80;
    var bits = len * 8;
    buf[total - 4] = bits >>> 24; buf[total - 3] = bits >>> 16; buf[total - 2] = bits >>> 8; buf[total - 1] = bits;
    for (var off = 0; off < total; off += 64) {
      for (var i = 0; i < 16; i++) { var j = off + i * 4; W[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3]; }
      for (i = 16; i < 64; i++) {
        var x = W[i - 15], y = W[i - 2];
        W[i] = (W[i - 16] + (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) + W[i - 7] +
          (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10))) | 0;
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (i = 0; i < 64; i++) {
        var t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
        var t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    return h0 >>> 0;
  }
  async function solve(n) {
    var limit = 0xffffffff >>> n;
    var prefix = new TextEncoder().encode('demo.' + Math.random().toString(36).slice(2) + ':');
    var bytes = new Uint8Array(prefix.length + 20); bytes.set(prefix);
    var t0 = performance.now();
    for (var k = 0; ; k++) {
      var s = String(k), len = prefix.length;
      for (var i = 0; i < s.length; i++) bytes[len++] = s.charCodeAt(i);
      if (sha256First(bytes, len) <= limit) return { tries: k + 1, ms: performance.now() - t0 };
      if ((k & 0x3fff) === 0) await new Promise(function (r) { setTimeout(r, 0); });
    }
  }

  // ---- hero diagram: an endless stream of people and bots ----
  (function () {
    var stage = document.querySelector('.viz-stage');
    if (!stage) return;
    var site = stage.querySelector('.n-site'), fd = stage.querySelector('.n-formd'), inbox = stage.querySelector('.n-inbox');
    var ticks = Array.prototype.slice.call(fd.querySelectorAll('[data-c]'));
    var why = fd.querySelector('.why'), rows = inbox.querySelector('.rows');
    var typed = site.querySelector('[data-type]'), send = site.querySelector('[data-send]');
    var nPass = document.querySelector('[data-pass]'), nStop = document.querySelector('[data-stop]');
    var pass = 0, stop = 0, i = 0, visible = true;
    var calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var people = t(['Anna', 'James', 'Kate', 'Mark', 'Olivia', 'Tom'], ['Anna', 'Piotr', 'Kasia', 'Marek', 'Ola', 'Tomek']);
    var bots = [
      { at: 'pulapka', why: t('honeypot filled: fake success', 'pole-pułapka wypełnione: udawany sukces') },
      { at: 'czas', why: t('sent after 0.3 s: 400', 'wysłane po 0,3 s: 400') },
      { at: 'token', why: t('no token, bot without JS: 400', 'brak tokenu, bot bez JS: 400') },
      { at: 'limit', why: t('6th submission in 10 min: 429', '6. zgłoszenie w 10 min: 429') },
      { at: 'duplikat', why: t('same content again: fake success', 'ta sama treść drugi raz: udawany sukces') }
    ];
    var plan = ['p', 'b', 'b', 'p', 'b', 'b', 'b', 'p', 'b', 'b'];
    var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
    function at(node, side) {
      var s = stage.getBoundingClientRect(), n = node.getBoundingClientRect();
      return { x: (side === 'in' ? n.left : n.right) - s.left, y: n.top - s.top + n.height / 2 };
    }
    function move(el, from, to, ms) {
      return el.animate([{ transform: 'translate(' + from.x + 'px,' + from.y + 'px) translate(-50%,-50%)' },
                         { transform: 'translate(' + to.x + 'px,' + to.y + 'px) translate(-50%,-50%)' }],
                        { duration: ms, easing: 'cubic-bezier(.4,0,.2,1)', fill: 'forwards' }).finished;
    }
    function addRow(name) {
      var li = document.createElement('li'), b = document.createElement('b'), sp = document.createElement('span');
      b.textContent = name; sp.textContent = t('new message', 'nowa wiadomość');
      li.append(b, sp); rows.prepend(li);
      while (rows.children.length > 4) rows.lastChild.remove();
    }
    async function one() {
      var human = plan[i % plan.length] === 'p';
      var bot = bots[i % bots.length], name = people[i % people.length];
      i++;
      // the visitor (or bot) types a name and presses Send
      typed.textContent = '';
      var label = human ? name : 'SEO PROMO!!!';
      for (var j = 1; j <= label.length; j++) { typed.textContent = label.slice(0, j); await sleep(human ? 55 : 12); }
      send.classList.add('press'); await sleep(140); send.classList.remove('press');
      var el = document.createElement('span');
      el.className = 'pkt' + (human ? '' : ' bot');
      el.textContent = human ? name : 'bot';
      stage.appendChild(el);
      var a = at(send, 'out'), c = at(fd, 'in');
      a.x -= 10; c.x += 18;
      await move(el, a, c, 650);
      el.style.opacity = '0';
      ticks.forEach(function (t) { t.className = ''; }); why.textContent = '';
      for (var k = 0; k < ticks.length; k++) {
        var t = ticks[k];
        if (!human && t.getAttribute('data-c') === bot.at) { t.className = 'bad'; why.textContent = bot.why; break; }
        t.className = 'ok'; await sleep(70);
      }
      if (!human) {
        stop++; nStop.textContent = stop;
        el.remove(); await sleep(900); return;
      }
      el.style.opacity = '';
      var d = at(fd, 'out'), e = at(inbox, 'in');
      d.x -= 18; e.x += 24;
      await move(el, d, e, 650);
      el.remove();
      pass++; nPass.textContent = pass; addRow(name);
      await sleep(500);
    }
    async function loop() {
      for (;;) {
        if (!visible || document.hidden) { await sleep(400); continue; }
        try { await one(); } catch (e) { await sleep(400); }
      }
    }
    if (calm) {
      addRow(people[2]); addRow(people[1]); addRow(people[0]);
      ticks.forEach(function (t) { t.className = t.getAttribute('data-c') === 'pulapka' ? 'bad' : (t.getAttribute('data-c') === 'duplikat' ? '' : 'ok'); });
      why.textContent = bots[0].why; nPass.textContent = '3'; nStop.textContent = '7';
      return;
    }
    if ('IntersectionObserver' in window) new IntersectionObserver(function (es) { visible = es[0].isIntersecting; }).observe(stage);
    loop();
  })();

  // ---- background: contour lines of fractal noise, drawn once per size ----
  (function () {
    var cv = document.querySelector('canvas.bg');
    if (!cv || !cv.getContext) return;
    // value noise with a fixed seed, summed over octaves (fBm)
    var P = new Uint8Array(512), seed = 7;
    for (var i = 0; i < 256; i++) P[i] = i;
    for (i = 255; i > 0; i--) { seed = (seed * 16807) % 2147483647; var j = seed % (i + 1), t = P[i]; P[i] = P[j]; P[j] = t; }
    for (i = 0; i < 256; i++) P[i + 256] = P[i];
    function hash(x, y) { return P[P[x & 255] + (y & 255)] / 255; }
    function sm(t) { return t * t * (3 - 2 * t); }
    function vnoise(x, y) {
      var xi = Math.floor(x), yi = Math.floor(y), xf = sm(x - xi), yf = sm(y - yi);
      var a = hash(xi, yi), b = hash(xi + 1, yi), c = hash(xi, yi + 1), d = hash(xi + 1, yi + 1);
      return a + (b - a) * xf + (c - a) * yf + (a - b - c + d) * xf * yf;
    }
    function fbm(x, y) { var v = 0, amp = 0.5, f = 1; for (var o = 0; o < 4; o++) { v += amp * vnoise(x * f, y * f); f *= 2.03; amp *= 0.5; } return v; }

    function draw() {
      var dpr = Math.min(window.devicePixelRatio || 1, 2), w = window.innerWidth, h = window.innerHeight;
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
      var g = cv.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
      var step = 10, cols = Math.ceil(w / step) + 1, rows = Math.ceil(h / step) + 1, sc = 1 / 260;
      var f = new Float32Array(cols * rows);
      for (var y = 0; y < rows; y++) for (var x = 0; x < cols; x++) f[y * cols + x] = fbm(x * step * sc + 3.1, y * step * sc + 1.7);
      var levels = 18;
      for (var L = 1; L < levels; L++) {
        var iso = 0.18 + L * (0.64 / levels);
        g.beginPath();
        for (y = 0; y < rows - 1; y++) for (x = 0; x < cols - 1; x++) {
          var a = f[y * cols + x], b = f[y * cols + x + 1], c = f[(y + 1) * cols + x + 1], d = f[(y + 1) * cols + x];
          var k = (a > iso ? 8 : 0) | (b > iso ? 4 : 0) | (c > iso ? 2 : 0) | (d > iso ? 1 : 0);
          if (k === 0 || k === 15) continue;
          var X = x * step, Y = y * step;
          var top = [X + step * (iso - a) / (b - a), Y], right = [X + step, Y + step * (iso - b) / (c - b)];
          var bot = [X + step * (iso - d) / (c - d), Y + step], left = [X, Y + step * (iso - a) / (d - a)];
          var segs = {1: [[left, bot]], 2: [[bot, right]], 3: [[left, right]], 4: [[top, right]], 5: [[left, top], [bot, right]], 6: [[top, bot]], 7: [[left, top]],
                      8: [[left, top]], 9: [[top, bot]], 10: [[top, right], [left, bot]], 11: [[top, right]], 12: [[left, right]], 13: [[bot, right]], 14: [[left, bot]]}[k];
          for (var sgi = 0; sgi < segs.length; sgi++) { g.moveTo(segs[sgi][0][0], segs[sgi][0][1]); g.lineTo(segs[sgi][1][0], segs[sgi][1][1]); }
        }
        g.strokeStyle = L % 4 === 0 ? 'rgba(11, 85, 246, 0.13)' : 'rgba(11, 85, 246, 0.065)';
        g.lineWidth = L % 4 === 0 ? 1.2 : 0.8;
        g.stroke();
      }
    }
    var timer = 0, lastW = 0;
    function redraw() { if (Math.abs(window.innerWidth - lastW) < 2 && cv.width) return; lastW = window.innerWidth; draw(); }
    window.addEventListener('resize', function () { clearTimeout(timer); timer = setTimeout(redraw, 200); });
    redraw();
  })();

  // ---- install guide: domain, variant, tabs, copy ----
  (function () {
    var setup = document.getElementById('setup');
    if (!setup) return;
    var input = setup.elements.domain, DEF = t('yoursite.com', 'twojastrona.pl');
    var clean = function (v) {
      v = v.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
      return /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(v) ? v : '';
    };
    function apply() {
      var d = clean(input.value) || DEF;
      var other = setup.querySelector('input[name=where]:checked').value === 'other';
      var host = other ? 'forms.' + d : d;
      document.querySelectorAll('[data-d]').forEach(function (n) { n.textContent = d; });
      document.querySelectorAll('[data-h]').forEach(function (n) { n.textContent = host; });
      document.querySelectorAll('[data-base]').forEach(function (n) { n.textContent = other ? 'https://' + host : ''; });
      document.querySelectorAll('.install [data-variant]').forEach(function (n) { n.hidden = n.getAttribute('data-variant') !== (other ? 'other' : 'same'); });
    }
    // "Copy instructions for AI": install.md with the person's setup on top,
    // so an assistant can deploy without asking for what is already known.
    // The file is fetched up front: Safari only allows a clipboard write
    // directly inside the click, not after a network round trip.
    var aiBtn = document.querySelector('[data-ai-copy]'), aiStatus = document.querySelector('[data-ai-status]'), aiDoc = null;
    if (aiBtn) fetch(aiBtn.getAttribute('data-src'), { credentials: 'omit' })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
      .then(function (md) { aiDoc = md; }, function () {});
    if (aiBtn) aiBtn.addEventListener('click', function () {
      var typed = clean(input.value), other = setup.querySelector('input[name=where]:checked').value === 'other';
      var head = [t('Help me deploy formd on my Linux server. Follow the instructions below step by step.', 'Pomóż mi wdrożyć formd na moim serwerze z Linuksem. Postępuj krok po kroku według instrukcji poniżej.'), '', 'My setup:'];
      head.push(typed ? '- Site domain: ' + typed : '- Site domain: ask me');
      head.push(other
        ? '- The site is hosted elsewhere (GitHub Pages, Netlify, S3). formd should run on this server at https://forms.' + (typed || '<domain>') + '/f/'
        : '- The site runs on this same server. formd should be at https://' + (typed || '<domain>') + '/f/');
      if (!EN) head.push('- Reply to me in Polish and set FORMD_LANG=pl.');
      var done = function (ok) {
        aiStatus.textContent = ok ? t('Copied. Paste it into your AI assistant.', 'Skopiowano. Wklej to swojemu asystentowi AI.') : t('Could not copy. Open install.md and copy it from there.', 'Nie udało się skopiować. Otwórz install.md i skopiuj stamtąd.');
        aiStatus.style.color = ok ? '' : 'var(--red)';
      };
      if (!aiDoc || !navigator.clipboard) { done(false); return; }
      navigator.clipboard.writeText(head.join('\n') + '\n\n---\n\n' + aiDoc).then(function () { done(true); }, function () { done(false); });
    });

    setup.addEventListener('input', apply);
    setup.addEventListener('change', apply);
    setup.addEventListener('submit', function (e) { e.preventDefault(); });
    apply();

    document.querySelectorAll('.install [data-tab]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var group = btn.getAttribute('data-tab'), name = btn.getAttribute('data-show');
        document.querySelectorAll('.install [data-tab="' + group + '"]').forEach(function (b) { b.setAttribute('aria-selected', b === btn); });
        document.querySelectorAll('.install [data-pane="' + group + '"]').forEach(function (p) { p.hidden = p.getAttribute('data-name') !== name; });
      });
    });

    document.querySelectorAll('.g-code').forEach(function (box) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'copy'; b.textContent = t('Copy', 'Kopiuj');
      b.addEventListener('click', function () {
        var pre = Array.prototype.filter.call(box.querySelectorAll('pre'), function (p) { return !p.hidden; })[0];
        var clone = pre.cloneNode(true);
        clone.querySelectorAll('[hidden]').forEach(function (h) { h.remove(); });
        var done = function (ok) { b.textContent = ok ? t('Copied', 'Skopiowano') : t('Select it manually', 'Zaznacz ręcznie'); setTimeout(function () { b.textContent = t('Copy', 'Kopiuj'); }, 1600); };
        if (navigator.clipboard) navigator.clipboard.writeText(clone.textContent).then(function () { done(true); }, function () { done(false); });
        else done(false);
      });
      var bar = document.createElement('div'), lab = document.createElement('span');
      bar.className = 'g-bar'; lab.textContent = box.getAttribute('data-label') || '';
      bar.append(lab, b);
      box.prepend(bar);
    });
  })();

  // ---- panel screenshots: tabs, arrow keys, address bar follows ----
  (function () {
    var tabs = Array.prototype.slice.call(document.querySelectorAll('.shot-list [role=tab]'));
    if (!tabs.length) return;
    var url = document.querySelector('[data-url].url');
    function pick(tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab, panel = document.getElementById(t.getAttribute('aria-controls'));
        t.setAttribute('aria-selected', on); t.tabIndex = on ? 0 : -1; panel.hidden = !on;
        if (on) url.textContent = panel.getAttribute('data-url');
      });
      if (focus) tab.focus();
    }
    tabs.forEach(function (t, i) {
      t.addEventListener('click', function () { pick(t); });
      t.addEventListener('keydown', function (e) {
        var j = (e.key === 'ArrowDown' || e.key === 'ArrowRight') ? i + 1 : (e.key === 'ArrowUp' || e.key === 'ArrowLeft') ? i - 1 : e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : null;
        if (j === null) return;
        e.preventDefault(); pick(tabs[(j + tabs.length) % tabs.length], true);
      });
    });
  })();

  var demo = document.getElementById('demo');
  if (!demo) return;

  var fmt = new Intl.NumberFormat(t('en-US', 'pl-PL'), { useGrouping: 'always' });
  var still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function wait(ms) { return new Promise(function (r) { setTimeout(r, still ? 0 : ms); }); }
  function q(sel) { return demo.querySelector(sel); }
  function secs(ms) { var v = (ms / 1000).toFixed(1); return (EN ? v : v.replace('.', ',')) + ' s'; }

  var form = q('#contact');
  var siteStatus = q('[data-site-status]');
  var trap = q('[data-trap]');
  var steps = {};
  demo.querySelectorAll('[data-step]').forEach(function (li) {
    steps[li.getAttribute('data-step')] = { li: li, span: li.querySelector('span'), idle: li.querySelector('span').textContent };
  });
  var order = ['token', 'pow', 'origin', 'rate', 'time', 'trap', 'dup', 'save'];
  var verdict = q('[data-verdict]'), req = q('[data-req]');
  var mails = q('[data-mails]'), count = q('[data-count]');
  var blockedBox = q('[data-blocked]'), blockedN = q('[data-blocked-n]');
  var buttons = demo.querySelectorAll('button[type=submit], [data-bot]');

  var HUMAN_IP = '203.0.113.7', BOT_IP = '198.51.100.23';
  var tokenAt = performance.now();
  var hits = {}, seen = {}, saved = 0, blocked = 0, last = null, busy = false;

  function setStep(name, cls, text) {
    var s = steps[name];
    s.li.className = cls || '';
    s.span.textContent = text || s.idle;
  }
  function resetSteps() { order.forEach(function (n) { setStep(n); }); verdict.className = 'verdict'; verdict.textContent = ''; }
  function skipFrom(name) { order.slice(order.indexOf(name) + 1).forEach(function (n) { setStep(n, 'skipped'); }); }
  function say(cls, strong, rest) {
    verdict.className = 'verdict ' + cls;
    verdict.textContent = '';
    var b = document.createElement('b'); b.textContent = strong;
    verdict.append(b, ' ' + rest);
  }
  function site(cls, text) { siteStatus.className = 'site-status ' + cls; siteStatus.textContent = text; }
  function lock(on) { busy = on; buttons.forEach(function (b) { b.disabled = on; }); }

  function addMail(to, subj, body) {
    var empty = mails.querySelector('.empty'); if (empty) empty.remove();
    var li = document.createElement('li'); li.className = 'mail';
    var a = document.createElement('div'); a.className = 'to'; a.textContent = t('To: ', 'Do: ') + to;
    var b = document.createElement('div'); b.className = 'subj'; b.textContent = subj;
    var c = document.createElement('div'); c.className = 'body'; c.textContent = body;
    li.append(a, b, c);
    mails.prepend(li);
    while (mails.children.length > 6) mails.lastChild.remove();
  }
  function bump() { blocked++; blockedN.textContent = blocked; blockedBox.hidden = false; }

  // check runs one submission through formd's checks and returns the outcome:
  // 'ok', 'fake' (bot told it succeeded, nothing stored) or an HTTP status.
  async function check(sub, pace) {
    resetSteps();
    req.textContent = sub.who + ', ' + sub.ip;
    var p = pace;

    setStep('token', 'run'); await wait(p);
    if (!sub.js) {
      setStep('token', 'bad', t('no token: without JavaScript there was nothing to sign', 'brak tokenu: bez JavaScriptu nie było czego podpisać'));
      skipFrom('token'); return 400;
    }
    setStep('token', 'ok', t('single-use, HMAC-signed, valid for 2 hours', 'jednorazowy, podpisany HMAC, ważny 2 godziny'));

    setStep('pow', 'run');
    var r = await solve(16); await wait(p);
    setStep('pow', 'ok', fmt.format(r.tries) + t(' SHA-256 tries in ', ' prób SHA-256 w ') + Math.max(1, Math.round(r.ms)) + ' ms');

    setStep('origin', 'run'); await wait(p);
    setStep('origin', 'ok', t('https://yoursite.com is on the list', 'https://twojastrona.pl jest na liście'));

    setStep('rate', 'run'); await wait(p);
    var now = Date.now(), list = (hits[sub.ip] || []).filter(function (t) { return now - t < 600000; });
    list.push(now); hits[sub.ip] = list;
    if (list.length > 5) {
      setStep('rate', 'bad', t('submission ' + list.length + ' from ' + sub.ip + ' in 10 minutes', list.length + '. zgłoszenie z ' + sub.ip + ' w 10 minut'));
      skipFrom('rate'); return 429;
    }
    setStep('rate', 'ok', list.length + t(' of 5 within 10 minutes', ' z 5 w ciągu 10 minut'));

    setStep('time', 'run'); await wait(p);
    if (sub.elapsed < 3000) {
      setStep('time', 'bad', t('sent ' + secs(sub.elapsed) + ' after the token was issued', 'wysłane ' + secs(sub.elapsed) + ' po pobraniu tokenu'));
      skipFrom('time'); return 400;
    }
    setStep('time', 'ok', secs(sub.elapsed) + t(' since the form was opened', ' od otwarcia formularza'));

    setStep('trap', 'run'); await wait(p);
    if (sub.website) {
      setStep('trap', 'fake', t('filled in: “' + sub.website.slice(0, 40) + '”', 'wypełnione: „' + sub.website.slice(0, 40) + '”'));
      skipFrom('trap'); return 'fake';
    }
    setStep('trap', 'ok', t('empty', 'puste'));

    setStep('dup', 'run'); await wait(p);
    var key = [sub.name, sub.email, sub.message].join('\u0000');
    if (seen[key]) {
      setStep('dup', 'fake', t('the same content is already in the database', 'ta sama treść już jest w bazie'));
      skipFrom('dup'); return 'fake';
    }
    setStep('dup', 'ok', t('new content', 'nowa treść'));

    setStep('save', 'run'); await wait(p);
    seen[key] = true;
    setStep('save', 'ok', t('saved, 2 emails queued', 'zapisano, 2 maile w kolejce'));
    return 'ok';
  }

  function deliver(sub) {
    saved++; count.textContent = saved;
    last = { name: sub.name, email: sub.email, message: sub.message };
    addMail(t('hello@yoursite.com', 'biuro@twojastrona.pl'), t('New message from ', 'Nowa wiadomość od ') + sub.name, sub.message);
    addMail(sub.email, t('Thanks for your message', 'Dziękujemy za wiadomość'), t('We will get back to you as soon as we can.', 'Odpowiemy najszybciej, jak się da.'));
  }

  function explain(res, bot) {
    if (res === 'ok') {
      say('ok', t('Passed.', 'Przeszło.'), bot ? t('This bot behaved like a person. That is what the optional content check by a language model is for, see below.', 'Ten bot zachowywał się jak człowiek. Na takie przypadki jest opcjonalna ocena treści polskim modelem, opisana niżej.') : t('The submission is in the database and the emails are queued. If the mail server does not answer, formd keeps retrying for up to 24 hours.', 'Zgłoszenie jest w bazie, a maile w kolejce. Gdy serwer poczty nie odpowiada, formd ponawia wysyłkę do 24 godzin.'));
      site('ok', t('Thank you! Your message has been sent.', 'Dziękujemy! Wiadomość została wysłana.'));
    } else if (res === 'fake') {
      say('fake', t('Fake success.', 'Udawany sukces.'), t('The bot gets “Thank you”, but nothing is saved and no email goes out. A real error would tell it how to get past the filter.', 'Bot dostaje „Dziękujemy”, ale nic nie zapisano i żaden mail nie wyszedł. Prawdziwy błąd podpowiedziałby mu, jak obejść filtr.'));
      site('ok', t('Thank you! Your message has been sent.', 'Dziękujemy! Wiadomość została wysłana.'));
    } else if (res === 429) {
      say('bad', 'HTTP 429.', t('Too many submissions from one address. Nothing was saved.', 'Za dużo zgłoszeń z jednego adresu. Nic nie zapisano.'));
      site('bad', t('too many submissions, try again later', 'zbyt wiele zgłoszeń, spróbuj później'));
    } else {
      say('bad', 'HTTP 400.', t('Submission rejected, nothing was saved.', 'Zgłoszenie odrzucone, nic nie zapisano.'));
      site('bad', steps.time.li.className === 'bad'
        ? t('the form was sent too quickly, try again in a moment', 'formularz wysłano zbyt szybko, spróbuj ponownie za chwilę')
        : t('verification failed, reload the page and try again', 'weryfikacja nie powiodła się, odśwież stronę i spróbuj ponownie'));
    }
  }

  // ---- you ----
  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (busy) return;
    var f = form.elements;
    var sub = { who: t('you', 'Ty'), ip: HUMAN_IP, js: true, name: f.name.value.trim(), email: f.email.value.trim(), message: f.message.value.trim(), website: '', elapsed: performance.now() - tokenAt };
    if (!sub.name || !sub.message || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sub.email)) { site('bad', t('Enter a name, a valid email address and a message.', 'Uzupełnij imię, poprawny e-mail i wiadomość.')); return; }
    lock(true); site('', t('Sending…', 'Wysyłanie…'));
    var res = await check(sub, 260);
    if (res === 'ok') deliver(sub);
    explain(res, false);
    tokenAt = performance.now(); // formd.js fetches a fresh token after each attempt
    lock(false);
  });

  // ---- bots ----
  var spam = { name: 'SEO Expert', email: 'seo@spam.example', message: t('Cheapest SEO links, buy now! http://spam.example', 'Najtańsze linki SEO, kup teraz! http://spam.example') };
  function bot(extra) {
    var s = { who: 'bot', ip: BOT_IP, js: true, website: '', elapsed: 5200 };
    Object.keys(spam).forEach(function (k) { s[k] = spam[k]; });
    Object.keys(extra || {}).forEach(function (k) { s[k] = extra[k]; });
    return s;
  }
  var scenarios = {
    nojs: async function () { return [await check(bot({ ip: '198.51.100.11', js: false }), 260)]; },
    fast: async function () { return [await check(bot({ ip: '198.51.100.12', elapsed: 400 }), 260)]; },
    trap: async function () {
      trap.hidden = false; trap.querySelector('input').value = 'http://spam.example';
      var r = await check(bot({ ip: '198.51.100.13', website: 'http://spam.example' }), 260);
      setTimeout(function () { trap.hidden = true; trap.querySelector('input').value = ''; }, still ? 0 : 2500);
      return [r];
    },
    dup: async function () {
      if (!last) { resetSteps(); say('fake', t('Send the form yourself first.', 'Najpierw wyślij formularz sam.'), t('This bot repeats the last submission that got through.', 'Ten bot powtarza ostatnie zgłoszenie, które przeszło.')); return []; }
      return [await check(bot({ ip: '198.51.100.14', name: last.name, email: last.email, message: last.message }), 260)];
    },
    flood: async function () {
      var out = [];
      for (var i = 1; i <= 10; i++) out.push(await check(bot({ elapsed: 300 + i * 40, message: spam.message + ' #' + i }), 40));
      return out;
    }
  };
  demo.querySelectorAll('[data-bot]').forEach(function (b) {
    b.addEventListener('click', async function () {
      if (busy) return;
      lock(true); site('', '');
      var name = b.getAttribute('data-bot');
      var res = await scenarios[name]();
      res.forEach(function (r) { if (r === 'ok') deliver(bot()); else bump(); });
      if (name === 'flood') {
        var n400 = res.filter(function (r) { return r === 400; }).length, n429 = res.filter(function (r) { return r === 429; }).length;
        var parts = [];
        if (n400) parts.push(t('too fast (400): ', 'za szybko (400): ') + n400);
        if (n429) parts.push(t('IP limit (429): ', 'limit dla IP (429): ') + n429);
        say('bad', t('10 submissions from one IP.', '10 zgłoszeń z jednego IP.'), t('Rejected: ', 'Odrzucone: ') + parts.join(', ') + t('. Nothing was saved.', '. Nic nie zapisano.'));
      } else if (res.length) explain(res[0], true);
      lock(false);
    });
  });

  // ---- reset ----
  q('[data-reset]').addEventListener('click', function () {
    if (busy) return;
    hits = {}; seen = {}; saved = 0; blocked = 0; last = null; tokenAt = performance.now();
    count.textContent = '0'; blockedBox.hidden = true;
    mails.textContent = '';
    var li = document.createElement('li'); li.className = 'empty'; li.textContent = t('Emails show up here when a submission gets through.', 'Tu pojawią się maile, gdy zgłoszenie przejdzie.');
    mails.appendChild(li);
    req.textContent = ''; site('', ''); resetSteps();
  });
})();
