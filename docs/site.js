/* formd.top — the live proof-of-work demo, the stage slider, the config
   generator and section entrances. Everything degrades to readable HTML. */
(function () {
  'use strict';
  document.documentElement.classList.add('js');

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

  var fmt = new Intl.NumberFormat('pl-PL');
  function secs(ms) { return ms < 1000 ? Math.max(1, Math.round(ms)) + ' ms' : (ms / 1000).toFixed(1).replace('.', ',') + ' s'; }
  function human(ms) {
    if (ms < 60000) return secs(ms);
    if (ms < 3600000) return Math.round(ms / 60000) + ' min';
    return (ms / 3600000).toFixed(1).replace('.', ',') + ' h';
  }

  // ---- proof-of-work demo ----
  var pow = document.getElementById('pow');
  if (pow) {
    var range = pow.querySelector('input[type=range]');
    var value = pow.querySelector('[data-bits]');
    var word = pow.querySelector('[data-word]');
    var go = pow.querySelector('.go');
    var out = { tries: pow.querySelector('[data-tries]'), time: pow.querySelector('[data-time]'), bot: pow.querySelector('[data-bot]') };
    var note = pow.querySelector('.note');
    var running = false;
    function plural(n) { return n === 1 ? 'bit' : (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20)) ? 'bity' : 'bitów'; }
    function show() {
      var n = +range.value;
      value.firstChild.nodeValue = n + ' ';
      value.querySelector('small').textContent = plural(n);
      word.textContent = n + ' ' + plural(n);
      out.tries.textContent = fmt.format(Math.pow(2, n));
      out.time.textContent = '—';
      out.bot.textContent = '—';
      pow.classList.toggle('hard', n >= 20);
      note.textContent = n >= 20 ? 'Na słabszym telefonie to już kilka sekund. Rozsądny zakres to 14–18 bitów.' : 'Średnia liczba prób rośnie dwukrotnie z każdym bitem.';
    }
    range.addEventListener('input', show);
    go.addEventListener('click', async function () {
      if (running) return;
      running = true; go.disabled = true; go.textContent = 'Liczę…';
      var n = +range.value, limit = n >= 32 ? 0 : (0xffffffff >>> n);
      var prefix = new TextEncoder().encode('demo.' + Math.random().toString(36).slice(2) + ':');
      var bytes = new Uint8Array(prefix.length + 20); bytes.set(prefix);
      var t0 = performance.now(), tries = 0;
      for (var k = 0; ; k++) {
        var s = String(k), len = prefix.length;
        for (var i = 0; i < s.length; i++) bytes[len++] = s.charCodeAt(i);
        tries++;
        if (sha256First(bytes, len) <= limit) break;
        if ((k & 0x3fff) === 0) await new Promise(function (r) { setTimeout(r, 0); });
      }
      var ms = performance.now() - t0;
      out.tries.textContent = fmt.format(tries);
      out.time.textContent = secs(ms);
      out.bot.textContent = human(ms * 1000);
      note.textContent = 'Twoja przeglądarka znalazła rozwiązanie po ' + fmt.format(tries) + ' próbach. Bot wysyłający tysiąc zgłoszeń musiałby to powtórzyć tysiąc razy.';
      go.disabled = false; go.textContent = 'Policz jeszcze raz'; running = false;
    });
    show();
  }

  // ---- stage slider ----
  var flow = document.getElementById('jak');
  if (flow) {
    var slider = flow.querySelector('.flow-ctl input');
    var stages = flow.querySelectorAll('[data-stage]');
    var names = flow.querySelectorAll('.flow-ctl li');
    var clauses = JSON.parse(flow.getAttribute('data-clauses'));
    var h2 = flow.querySelector('.clause h2'), p = flow.querySelector('.clause p');
    function stage() {
      var i = +slider.value;
      stages.forEach(function (el, k) { el.classList.toggle('on', k === i); });
      names.forEach(function (el, k) { el.classList.toggle('on', k === i); });
      h2.textContent = clauses[i][0]; p.textContent = clauses[i][1];
      slider.setAttribute('aria-valuetext', names[i].textContent);
    }
    slider.addEventListener('input', stage);
    stage();
  }

  // ---- config generator ----
  var form = document.getElementById('generator');
  if (form) {
    var input = form.querySelector('input');
    var slots = document.querySelectorAll('[data-domain]');
    var clean = function (v) {
      v = v.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      return /^[a-z0-9.-]{1,253}\.[a-z]{2,}$/.test(v) ? v : '';
    };
    function apply() {
      var d = clean(input.value) || 'example.com';
      slots.forEach(function (el) { el.textContent = d; });
    }
    input.addEventListener('input', apply);
    form.addEventListener('submit', function (e) {
      e.preventDefault(); apply();
      document.getElementById('przepis').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  // ---- entrances ----
  var items = document.querySelectorAll('[data-rise]');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); } });
    }, { rootMargin: '0px 0px -8% 0px' });
    items.forEach(function (el) { io.observe(el); });
  } else {
    items.forEach(function (el) { el.classList.add('in'); });
  }
})();
