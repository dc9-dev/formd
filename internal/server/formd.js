/* formd client: fetches a signed challenge, solves the proof-of-work and
 * submits the form. Usage:
 *   <form action="/f/contact" method="post" data-formd> ... </form>
 *   <script src="/f/formd.js" defer></script>
 * data-formd="ajax" submits with fetch and writes the result into the element
 * marked [data-formd-status] inside the form; otherwise a normal POST is made
 * (server redirects to the configured success/error page).
 */
(function () {
  'use strict';

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

  // Returns the first 32-bit word of SHA-256(bytes); enough to count leading
  // zero bits up to 32.
  function sha256First(bytes, len) {
    var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    var total = ((len + 9 + 63) >> 6) << 6;
    var buf = new Uint8Array(total);
    buf.set(bytes.subarray(0, len));
    buf[len] = 0x80;
    var bitLen = len * 8;
    buf[total - 4] = bitLen >>> 24; buf[total - 3] = bitLen >>> 16;
    buf[total - 2] = bitLen >>> 8; buf[total - 1] = bitLen;
    for (var off = 0; off < total; off += 64) {
      for (var i = 0; i < 16; i++) {
        var j = off + i * 4;
        W[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
      }
      for (i = 16; i < 64; i++) {
        var x = W[i - 15], y = W[i - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + W[i]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    return h0 >>> 0;
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  async function solve(token, bits) {
    if (bits <= 0) return '0';
    var prefix = new TextEncoder().encode(token + ':');
    var bytes = new Uint8Array(prefix.length + 20);
    bytes.set(prefix);
    var limit = bits >= 32 ? 0 : (0xffffffff >>> bits);
    for (var n = 0; ; n++) {
      var s = String(n), len = prefix.length;
      for (var i = 0; i < s.length; i++) bytes[len++] = s.charCodeAt(i);
      if (sha256First(bytes, len) <= limit) return s;
      if ((n & 0x3fff) === 0) await sleep(0); // keep the page responsive
    }
  }

  function setField(form, name, value) {
    var el = form.querySelector('input[name="' + name + '"]');
    if (!el) {
      el = document.createElement('input');
      el.type = 'hidden';
      el.name = name;
      form.appendChild(el);
    }
    el.value = value;
  }

  function setup(form) {
    var action = form.getAttribute('action');
    var state = null;

    function fetchChallenge() {
      state = fetch(action + '/challenge', { credentials: 'omit', headers: { Accept: 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error('challenge ' + r.status); return r.json(); })
        .then(function (c) { c.at = Date.now(); return c; });
      state.catch(function () {});
    }
    fetchChallenge();

    function status(msg, ok) {
      var el = form.querySelector('[data-formd-status]');
      if (el) { el.textContent = msg; el.dataset.state = ok ? 'ok' : 'error'; }
    }

    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      var btn = form.querySelector('[type="submit"]');
      if (btn) btn.disabled = true;
      status('Wysyłanie…', true);
      try {
        var c = await state.catch(function () { fetchChallenge(); return state; });
        if (Date.now() - c.at > 90 * 60 * 1000) { fetchChallenge(); c = await state; }
        var wait = c.min_seconds * 1000 + 500 - (Date.now() - c.at);
        var pow = await solve(c.token, c.bits);
        if (wait > 0) await sleep(wait);
        setField(form, '_challenge', c.token);
        setField(form, '_pow', pow);

        if (form.getAttribute('data-formd') !== 'ajax') {
          HTMLFormElement.prototype.submit.call(form);
          return;
        }
        var res = await fetch(action, {
          method: 'POST', credentials: 'omit',
          headers: { Accept: 'application/json' },
          body: new URLSearchParams(new FormData(form))
        });
        var data = await res.json().catch(function () { return {}; });
        if (data.ok) {
          form.reset();
          status(form.getAttribute('data-formd-success') || 'Dziękujemy! Wiadomość została wysłana.', true);
        } else {
          var errs = data.errors || {};
          status(Object.keys(errs).map(function (k) { return (k === '_form' ? '' : k + ': ') + errs[k]; }).join('\n') || 'Nie udało się wysłać formularza.', false);
        }
      } catch (e) {
        status('Nie udało się wysłać formularza. Spróbuj ponownie.', false);
      } finally {
        fetchChallenge(); // tokens are single-use
        if (btn) btn.disabled = false;
      }
    });
  }

  function init() {
    var list = document.querySelectorAll('form[data-formd]');
    for (var i = 0; i < list.length; i++) setup(list[i]);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
