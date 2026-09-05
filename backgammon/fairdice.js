/* The dice protocol of Backgammon by Arcane Void, in plain JavaScript.
   No dependencies, nothing asynchronous, so it runs anywhere and can be
   read in one sitting. Must agree with verify_dice.py and the app.

     seal        = SHA-256(seed || 16 zero bytes)
     commitment  = SHA-256(seed || salt)
     block(t, c) = HMAC-SHA-256(key = seed, msg = salt || u32le(t) || u32le(c))
     roll t      = first two bytes b < 252 of block(t,0), block(t,1), ...
                   each read as (b mod 6) + 1
*/
var FairDice = (function () {
  'use strict';

  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  /* SHA-256 of an array of bytes (0..255); returns an array of 32 bytes. */
  function sha256(msg) {
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var bytes = msg.slice();
    var bitLen = msg.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    // 64-bit big-endian length; messages here are far below 2^32 bits
    bytes.push(0, 0, 0, 0,
      (bitLen >>> 24) & 0xff, (bitLen >>> 16) & 0xff, (bitLen >>> 8) & 0xff, bitLen & 0xff);
    var w = new Array(64);
    for (var off = 0; off < bytes.length; off += 64) {
      for (var i = 0; i < 16; i++) {
        var j = off + 4 * i;
        w[i] = ((bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3]) >>> 0;
      }
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = [];
    for (i = 0; i < 8; i++) out.push((h[i] >>> 24) & 0xff, (h[i] >>> 16) & 0xff, (h[i] >>> 8) & 0xff, h[i] & 0xff);
    return out;
  }

  /* HMAC-SHA-256 with a 32-byte key. */
  function hmac(key, msg) {
    var ipad = [], opad = [];
    for (var i = 0; i < 64; i++) {
      var k = i < key.length ? key[i] : 0;
      ipad.push(k ^ 0x36); opad.push(k ^ 0x5c);
    }
    return sha256(opad.concat(sha256(ipad.concat(msg))));
  }

  function u32le(n) { return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]; }

  function toHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return s;
  }

  function fromHex(hex) {
    var out = [];
    for (var i = 0; i < hex.length; i += 2) out.push(parseInt(hex.substr(i, 2), 16));
    return out;
  }

  function zeros(n) { var a = []; while (n-- > 0) a.push(0); return a; }

  function seal(seed) { return toHex(sha256(seed.concat(zeros(16)))); }

  function commitment(seed, salt) { return toHex(sha256(seed.concat(salt))); }

  /* Dice for throw `turn` (counting from 0). Returns [d1, d2]. */
  function dice(seed, salt, turn) {
    var out = [], counter = 0;
    while (out.length < 2) {
      var h = hmac(seed, salt.concat(u32le(turn), u32le(counter)));
      for (var i = 0; i < h.length && out.length < 2; i++) {
        if (h[i] < 252) out.push(h[i] % 6 + 1);
      }
      counter++;
    }
    return out;
  }

  /* "3-1 52 7:66" -> [{turn:0,dice:[3,1]},{turn:1,dice:[5,2]},{turn:7,dice:[6,6]}] */
  function parseRolls(text) {
    var out = [], turn = 0;
    var tokens = text.replace(/,/g, ' ').split(/\s+/).filter(function (t) { return t.length > 0; });
    for (var i = 0; i < tokens.length; i++) {
      var tok = tokens[i];
      var m = tok.match(/^(\d+):(.*)$/);
      if (m) { turn = parseInt(m[1], 10); tok = m[2]; }
      var digits = tok.replace(/[^0-9]/g, '');
      if (digits.length !== 2 || /[07-9]/.test(digits)) {
        throw new Error('"' + tokens[i] + '" is not a throw. Write each throw as two dice, 1 to 6, like 31 or 3-1.');
      }
      out.push({ turn: turn, dice: [parseInt(digits[0], 10), parseInt(digits[1], 10)] });
      turn++;
    }
    return out;
  }

  return { sha256: sha256, hmac: hmac, toHex: toHex, fromHex: fromHex,
           seal: seal, commitment: commitment, dice: dice, parseRolls: parseRolls };
})();
