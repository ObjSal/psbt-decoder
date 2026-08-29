// Base58Check, Bech32 / Bech32m and BIP32 key-path helpers.
(function (root) {
  'use strict';
  const { Crypto, Bytes } = root;

  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function base58Encode(bytes) {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    let s = '';
    while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
    return '1'.repeat(zeros) + s;
  }

  function base58Decode(str) {
    let n = 0n;
    for (const ch of str) {
      const i = B58.indexOf(ch);
      if (i < 0) throw new Error('Invalid base58 character');
      n = n * 58n + BigInt(i);
    }
    const bytes = [];
    while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
    let zeros = 0;
    while (zeros < str.length && str[zeros] === '1') zeros++;
    return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
  }

  function base58Check(payload) {
    const chk = Crypto.hash256(payload).slice(0, 4);
    return base58Encode(Bytes.concat(payload, chk));
  }

  // ---- bech32 / bech32m
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk >>> 0;
  }
  function hrpExpand(hrp) {
    const out = [];
    for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
    out.push(0);
    for (const c of hrp) out.push(c.charCodeAt(0) & 31);
    return out;
  }
  function convertBits(data, from, to, pad) {
    let acc = 0, bits = 0; const out = []; const maxv = (1 << to) - 1;
    for (const v of data) {
      acc = (acc << from) | v; bits += from;
      while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
    }
    if (pad) { if (bits > 0) out.push((acc << (to - bits)) & maxv); }
    else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('Invalid padding');
    return out;
  }
  function bech32Encode(hrp, data, bech32m) {
    const consts = bech32m ? 0x2bc830a3 : 1;
    const values = hrpExpand(hrp).concat(data);
    const pm = polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ consts;
    let s = hrp + '1';
    for (const d of data) s += CHARSET[d];
    for (let i = 0; i < 6; i++) s += CHARSET[(pm >> (5 * (5 - i))) & 31];
    return s;
  }
  function segwitAddress(hrp, version, program) {
    const data = [version].concat(convertBits(program, 8, 5, true));
    return bech32Encode(hrp, data, version > 0);
  }

  // ---- BIP32 helpers
  function pathToString(pathU32s) {
    if (!pathU32s.length) return 'm';
    return 'm/' + pathU32s.map(i => (i >= 0x80000000 ? (i - 0x80000000) + "'" : String(i))).join('/');
  }
  function parseDerivation(valueBytes) {
    // fingerprint (4 bytes) followed by u32 LE path elements
    if (valueBytes.length < 4 || (valueBytes.length - 4) % 4) throw new Error('Invalid BIP32 derivation value');
    const dv = new DataView(valueBytes.buffer, valueBytes.byteOffset, valueBytes.byteLength);
    const path = [];
    for (let i = 4; i < valueBytes.length; i += 4) path.push(dv.getUint32(i, true));
    return { fingerprint: Bytes.bytesToHex(valueBytes.slice(0, 4)), path, pathStr: pathToString(path) };
  }
  function decodeXpub(bytes78) {
    if (bytes78.length !== 78) throw new Error('xpub must be 78 bytes');
    const dv = new DataView(bytes78.buffer, bytes78.byteOffset, bytes78.byteLength);
    const version = dv.getUint32(0);
    const VERSIONS = {
      0x0488b21e: 'xpub (mainnet)', 0x043587cf: 'tpub (testnet)', 0x049d7cb2: 'ypub', 0x044a5262: 'upub',
      0x04b24746: 'zpub', 0x045f1cf6: 'vpub', 0x0295b43f: 'Ypub', 0x02aa7ed3: 'Zpub', 0x024289ef: 'Upub', 0x02575483: 'Vpub',
    };
    return {
      versionName: VERSIONS[version] || ('unknown 0x' + version.toString(16)),
      depth: bytes78[4],
      parentFingerprint: Bytes.bytesToHex(bytes78.slice(5, 9)),
      childIndex: dv.getUint32(9),
      chainCode: Bytes.bytesToHex(bytes78.slice(13, 45)),
      pubkey: Bytes.bytesToHex(bytes78.slice(45, 78)),
      encoded: base58Check(bytes78),
      fingerprint: Bytes.bytesToHex(Crypto.hash160(bytes78.slice(45, 78)).slice(0, 4)),
    };
  }

  root.Encoding = { base58Encode, base58Decode, base58Check, segwitAddress, bech32Encode, pathToString, parseDerivation, decodeXpub };
})(typeof window !== 'undefined' ? window : globalThis);
