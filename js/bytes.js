// Byte helpers: hex / base64 conversion and a cursor-based reader with segment recording.
(function (root) {
  'use strict';

  function hexToBytes(hex) {
    hex = hex.replace(/\s+/g, '');
    if (hex.length % 2) throw new Error('Hex string has odd length');
    if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('Invalid hex characters');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }

  function base64ToBytes(b64) {
    b64 = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function reverse(bytes) {
    return Uint8Array.from(bytes).reverse();
  }

  function concat(...arrs) {
    const len = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }

  function equal(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  function isHex(s) { return /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0; }
  function isBase64(s) { return /^[A-Za-z0-9+/_-]+=*$/.test(s); }

  // Compact-size (varint) encoding
  function varintBytes(n) {
    if (n < 0xfd) return Uint8Array.of(n);
    if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
    if (n <= 0xffffffff) return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
    const b = new Uint8Array(9); b[0] = 0xff;
    let v = BigInt(n);
    for (let i = 1; i < 9; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  }

  function u32le(n) { return Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff); }
  function u64le(big) {
    const b = new Uint8Array(8); let v = BigInt(big);
    for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  }

  /**
   * Reader over a Uint8Array. Records "segments" ({start,end,label,cls,value}) that the UI
   * uses for the annotated-hex view.
   */
  class Reader {
    constructor(bytes, pos = 0, segments = null, base = 0) {
      this.bytes = bytes;
      this.pos = pos;
      this.segments = segments || [];
      this.base = base; // offset added to recorded segment positions
      this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    }
    get remaining() { return this.bytes.length - this.pos; }
    get eof() { return this.pos >= this.bytes.length; }
    need(n) { if (this.pos + n > this.bytes.length) throw new Error(`Unexpected end of data at byte ${this.pos} (need ${n} more)`); }
    u8() { this.need(1); return this.bytes[this.pos++]; }
    u16() { this.need(2); const v = this.dv.getUint16(this.pos, true); this.pos += 2; return v; }
    u32() { this.need(4); const v = this.dv.getUint32(this.pos, true); this.pos += 4; return v; }
    i32() { this.need(4); const v = this.dv.getInt32(this.pos, true); this.pos += 4; return v; }
    u64() { this.need(8); const v = this.dv.getBigUint64(this.pos, true); this.pos += 8; return v; }
    varint() {
      const b = this.u8();
      if (b < 0xfd) return b;
      if (b === 0xfd) return this.u16();
      if (b === 0xfe) return this.u32();
      const big = this.u64();
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('varint too large');
      return Number(big);
    }
    bytes_(n) { this.need(n); const out = this.bytes.slice(this.pos, this.pos + n); this.pos += n; return out; }
    varbytes() { const n = this.varint(); return this.bytes_(n); }
    // Record a segment for whatever fn reads.
    seg(label, cls, fn) {
      const start = this.pos;
      const value = fn();
      this.segments.push({ start: start + this.base, end: this.pos + this.base, label, cls, value });
      return value;
    }
  }

  root.Bytes = { hexToBytes, bytesToHex, base64ToBytes, bytesToBase64, reverse, concat, equal, isHex, isBase64, varintBytes, u32le, u64le, Reader };
})(typeof window !== 'undefined' ? window : globalThis);
