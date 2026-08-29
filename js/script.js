// Bitcoin Script: opcode table, disassembler, output-script classification and addresses.
(function (root) {
  'use strict';
  const { Crypto, Bytes, Encoding } = root;

  const OPS = {
    0x00: 'OP_0', 0x4c: 'OP_PUSHDATA1', 0x4d: 'OP_PUSHDATA2', 0x4e: 'OP_PUSHDATA4', 0x4f: 'OP_1NEGATE', 0x50: 'OP_RESERVED',
    0x51: 'OP_1', 0x52: 'OP_2', 0x53: 'OP_3', 0x54: 'OP_4', 0x55: 'OP_5', 0x56: 'OP_6', 0x57: 'OP_7', 0x58: 'OP_8',
    0x59: 'OP_9', 0x5a: 'OP_10', 0x5b: 'OP_11', 0x5c: 'OP_12', 0x5d: 'OP_13', 0x5e: 'OP_14', 0x5f: 'OP_15', 0x60: 'OP_16',
    0x61: 'OP_NOP', 0x62: 'OP_VER', 0x63: 'OP_IF', 0x64: 'OP_NOTIF', 0x65: 'OP_VERIF', 0x66: 'OP_VERNOTIF', 0x67: 'OP_ELSE',
    0x68: 'OP_ENDIF', 0x69: 'OP_VERIFY', 0x6a: 'OP_RETURN', 0x6b: 'OP_TOALTSTACK', 0x6c: 'OP_FROMALTSTACK', 0x6d: 'OP_2DROP',
    0x6e: 'OP_2DUP', 0x6f: 'OP_3DUP', 0x70: 'OP_2OVER', 0x71: 'OP_2ROT', 0x72: 'OP_2SWAP', 0x73: 'OP_IFDUP', 0x74: 'OP_DEPTH',
    0x75: 'OP_DROP', 0x76: 'OP_DUP', 0x77: 'OP_NIP', 0x78: 'OP_OVER', 0x79: 'OP_PICK', 0x7a: 'OP_ROLL', 0x7b: 'OP_ROT',
    0x7c: 'OP_SWAP', 0x7d: 'OP_TUCK', 0x7e: 'OP_CAT', 0x7f: 'OP_SUBSTR', 0x80: 'OP_LEFT', 0x81: 'OP_RIGHT', 0x82: 'OP_SIZE',
    0x83: 'OP_INVERT', 0x84: 'OP_AND', 0x85: 'OP_OR', 0x86: 'OP_XOR', 0x87: 'OP_EQUAL', 0x88: 'OP_EQUALVERIFY',
    0x89: 'OP_RESERVED1', 0x8a: 'OP_RESERVED2', 0x8b: 'OP_1ADD', 0x8c: 'OP_1SUB', 0x8d: 'OP_2MUL', 0x8e: 'OP_2DIV',
    0x8f: 'OP_NEGATE', 0x90: 'OP_ABS', 0x91: 'OP_NOT', 0x92: 'OP_0NOTEQUAL', 0x93: 'OP_ADD', 0x94: 'OP_SUB', 0x95: 'OP_MUL',
    0x96: 'OP_DIV', 0x97: 'OP_MOD', 0x98: 'OP_LSHIFT', 0x99: 'OP_RSHIFT', 0x9a: 'OP_BOOLAND', 0x9b: 'OP_BOOLOR',
    0x9c: 'OP_NUMEQUAL', 0x9d: 'OP_NUMEQUALVERIFY', 0x9e: 'OP_NUMNOTEQUAL', 0x9f: 'OP_LESSTHAN', 0xa0: 'OP_GREATERTHAN',
    0xa1: 'OP_LESSTHANOREQUAL', 0xa2: 'OP_GREATERTHANOREQUAL', 0xa3: 'OP_MIN', 0xa4: 'OP_MAX', 0xa5: 'OP_WITHIN',
    0xa6: 'OP_RIPEMD160', 0xa7: 'OP_SHA1', 0xa8: 'OP_SHA256', 0xa9: 'OP_HASH160', 0xaa: 'OP_HASH256',
    0xab: 'OP_CODESEPARATOR', 0xac: 'OP_CHECKSIG', 0xad: 'OP_CHECKSIGVERIFY', 0xae: 'OP_CHECKMULTISIG',
    0xaf: 'OP_CHECKMULTISIGVERIFY', 0xb0: 'OP_NOP1', 0xb1: 'OP_CHECKLOCKTIMEVERIFY', 0xb2: 'OP_CHECKSEQUENCEVERIFY',
    0xb3: 'OP_NOP4', 0xb4: 'OP_NOP5', 0xb5: 'OP_NOP6', 0xb6: 'OP_NOP7', 0xb7: 'OP_NOP8', 0xb8: 'OP_NOP9', 0xb9: 'OP_NOP10',
    0xba: 'OP_CHECKSIGADD', 0xff: 'OP_INVALIDOPCODE',
  };
  const DISABLED = new Set([0x7e, 0x7f, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x8d, 0x8e, 0x95, 0x96, 0x97, 0x98, 0x99]);

  const NETWORKS = {
    mainnet: { name: 'Bitcoin mainnet', p2pkh: 0x00, p2sh: 0x05, hrp: 'bc' },
    testnet: { name: 'Testnet', p2pkh: 0x6f, p2sh: 0xc4, hrp: 'tb' },
    signet:  { name: 'Signet', p2pkh: 0x6f, p2sh: 0xc4, hrp: 'tb' },
    regtest: { name: 'Regtest', p2pkh: 0x6f, p2sh: 0xc4, hrp: 'bcrt' },
  };

  /** Disassemble a script into tokens: {op, name, data?, offset, len, error?} */
  function disassemble(bytes) {
    const tokens = [];
    let i = 0;
    while (i < bytes.length) {
      const op = bytes[i];
      const tok = { op, offset: i };
      if (op >= 0x01 && op <= 0x4e) {
        let n, hdr;
        if (op <= 0x4b) { n = op; hdr = 1; tok.name = `PUSH(${n})`; }
        else if (op === 0x4c) { hdr = 2; n = bytes[i + 1]; tok.name = 'OP_PUSHDATA1'; }
        else if (op === 0x4d) { hdr = 3; n = bytes[i + 1] | (bytes[i + 2] << 8); tok.name = 'OP_PUSHDATA2'; }
        else { hdr = 5; n = (bytes[i + 1] | (bytes[i + 2] << 8) | (bytes[i + 3] << 16) | (bytes[i + 4] << 24)) >>> 0; tok.name = 'OP_PUSHDATA4'; }
        if (n === undefined || i + hdr + n > bytes.length) {
          tok.error = 'push exceeds script length';
          tok.data = bytes.slice(i + hdr);
          tok.len = bytes.length - i;
          tokens.push(tok);
          break;
        }
        tok.data = bytes.slice(i + hdr, i + hdr + n);
        tok.len = hdr + n;
        i += hdr + n;
      } else {
        tok.name = OPS[op] || `OP_UNKNOWN(0x${op.toString(16).padStart(2, '0')})`;
        if (op === 0 ) tok.data = new Uint8Array(0);
        if (op >= 0x51 && op <= 0x60) tok.num = op - 0x50;
        if (op === 0x4f) tok.num = -1;
        if (DISABLED.has(op)) tok.disabled = true;
        tok.len = 1;
        i += 1;
      }
      tokens.push(tok);
    }
    return tokens;
  }

  function asm(bytes) {
    return disassemble(bytes).map(t => t.data && t.data.length ? Bytes.bytesToHex(t.data) : (t.data ? 'OP_0' : t.name)).join(' ');
  }

  const isPubkey = (d) => d && ((d.length === 33 && (d[0] === 2 || d[0] === 3)) || (d.length === 65 && d[0] === 4));
  const isDERSig = (d) => d && d.length >= 9 && d.length <= 73 && d[0] === 0x30 && d[1] === d.length - 3;
  const isSchnorrSig = (d) => d && (d.length === 64 || d.length === 65);

  /** Classify an output script (scriptPubKey). */
  function classifyOutput(script, networkName = 'mainnet') {
    const net = NETWORKS[networkName] || NETWORKS.mainnet;
    const t = disassemble(script);
    const res = { type: 'nonstandard', address: null, description: 'Non-standard script', asm: asm(script) };
    const hex = (d) => Bytes.bytesToHex(d);
    if (script.length === 0) return { ...res, type: 'empty', description: 'Empty script (unspendable)' };
    // P2PKH
    if (t.length === 5 && t[0].op === 0x76 && t[1].op === 0xa9 && t[2].data && t[2].data.length === 20 && t[3].op === 0x88 && t[4].op === 0xac) {
      return { ...res, type: 'p2pkh', hash: hex(t[2].data), address: Encoding.base58Check(Bytes.concat(Uint8Array.of(net.p2pkh), t[2].data)), description: 'Pay-to-Public-Key-Hash (legacy)' };
    }
    // P2SH
    if (t.length === 3 && t[0].op === 0xa9 && t[1].data && t[1].data.length === 20 && t[2].op === 0x87) {
      return { ...res, type: 'p2sh', hash: hex(t[1].data), address: Encoding.base58Check(Bytes.concat(Uint8Array.of(net.p2sh), t[1].data)), description: 'Pay-to-Script-Hash (legacy wrapper)' };
    }
    // Witness programs
    if (t.length === 2 && (t[0].op === 0 || (t[0].op >= 0x51 && t[0].op <= 0x60)) && t[1].data && t[1].data.length >= 2 && t[1].data.length <= 40 && t[1].len === t[1].data.length + 1) {
      const ver = t[0].op === 0 ? 0 : t[0].op - 0x50;
      const prog = t[1].data;
      const address = Encoding.segwitAddress(net.hrp, ver, prog);
      if (ver === 0 && prog.length === 20) return { ...res, type: 'p2wpkh', hash: hex(prog), address, description: 'Pay-to-Witness-Public-Key-Hash (native SegWit v0)' };
      if (ver === 0 && prog.length === 32) return { ...res, type: 'p2wsh', hash: hex(prog), address, description: 'Pay-to-Witness-Script-Hash (native SegWit v0)' };
      if (ver === 1 && prog.length === 32) return { ...res, type: 'p2tr', hash: hex(prog), address, description: 'Pay-to-Taproot (SegWit v1)' };
      return { ...res, type: 'witness_unknown', witnessVersion: ver, hash: hex(prog), address, description: `Unknown witness program v${ver} (${prog.length} bytes)` };
    }
    // P2PK
    if (t.length === 2 && isPubkey(t[0].data) && t[1].op === 0xac) {
      return { ...res, type: 'p2pk', pubkey: hex(t[0].data), address: null, description: 'Pay-to-Public-Key (bare, legacy)' };
    }
    // OP_RETURN
    if (t[0].op === 0x6a) {
      const pushes = t.slice(1).filter(x => x.data).map(x => x.data);
      const total = Bytes.concat(...pushes);
      let text = null;
      try {
        const s = new TextDecoder('utf-8', { fatal: true }).decode(total);
        if (/^[\x20-\x7e\t\r\n -￿]*$/.test(s)) text = s;
      } catch (e) { /* not utf8 */ }
      return { ...res, type: 'op_return', data: hex(total), dataText: text, description: `OP_RETURN data carrier (${total.length} bytes, provably unspendable)` };
    }
    // Bare multisig
    const ms = parseMultisig(t);
    if (ms) return { ...res, type: 'multisig', ...ms, description: `Bare ${ms.m}-of-${ms.n} multisig` };
    return res;
  }

  function parseMultisig(t) {
    if (t.length < 4) return null;
    const last = t[t.length - 1];
    if (last.op !== 0xae && last.op !== 0xaf) return null;
    const mTok = t[0], nTok = t[t.length - 2];
    if (mTok.num === undefined || nTok.num === undefined) return null;
    const keys = t.slice(1, -2);
    if (keys.length !== nTok.num || !keys.every(k => isPubkey(k.data))) return null;
    if (mTok.num < 1 || mTok.num > nTok.num) return null;
    return { m: mTok.num, n: nTok.num, pubkeys: keys.map(k => Bytes.bytesToHex(k.data)) };
  }

  /**
   * Classify an "inner" script: a redeemScript, witnessScript or tapleaf script.
   * Returns {type, description, m?, n?, pubkeys?, features:[]}.
   */
  function classifyInner(script, networkName = 'mainnet') {
    const t = disassemble(script);
    const outer = classifyOutput(script, networkName);
    const features = [];
    const names = t.map(x => x.name);
    if (names.includes('OP_CHECKLOCKTIMEVERIFY')) features.push('absolute timelock (CLTV)');
    if (names.includes('OP_CHECKSEQUENCEVERIFY')) features.push('relative timelock (CSV)');
    if (names.includes('OP_IF') || names.includes('OP_NOTIF')) features.push('conditional branches');
    if (names.some(n => /OP_(SHA256|HASH160|HASH256|RIPEMD160)/.test(n))) features.push('hash preimage condition');
    if (names.includes('OP_CHECKSIGADD')) features.push('tapscript multisig (CHECKSIGADD)');
    if (t.some(x => x.disabled)) features.push('DISABLED opcode present (unspendable)');
    if (t.some(x => x.error)) features.push('MALFORMED push');

    const ms = parseMultisig(t);
    if (ms) return { type: 'multisig', description: `${ms.m}-of-${ms.n} multisig: requires ${ms.m} signature${ms.m > 1 ? 's' : ''} from ${ms.n} keys`, ...ms, features, asm: asm(script) };
    if (outer.type === 'p2wpkh') return { type: 'p2wpkh', description: 'Nested P2WPKH (P2SH-P2WPKH wrapped SegWit)', hash: outer.hash, features, asm: asm(script) };
    if (outer.type === 'p2wsh') return { type: 'p2wsh', description: 'Nested P2WSH (P2SH-P2WSH wrapped SegWit)', hash: outer.hash, features, asm: asm(script) };
    if (outer.type === 'p2pkh') return { type: 'p2pkh', description: 'P2PKH script (single key)', hash: outer.hash, features, asm: asm(script) };
    if (outer.type === 'p2pk') return { type: 'p2pk', description: 'Single-key CHECKSIG', pubkey: outer.pubkey, features, asm: asm(script) };
    // tapscript single key: <xonly> OP_CHECKSIG
    if (t.length === 2 && t[0].data && t[0].data.length === 32 && t[1].op === 0xac) {
      return { type: 'tapscript_pk', description: 'Tapscript single-key CHECKSIG', pubkey: Bytes.bytesToHex(t[0].data), features, asm: asm(script) };
    }
    // tapscript k-of-n: <pk> CHECKSIG <pk> CHECKSIGADD ... <k> NUMEQUAL
    if (names.includes('OP_CHECKSIGADD') && (names[names.length - 1] === 'OP_NUMEQUAL' || names[names.length - 1] === 'OP_NUMEQUALVERIFY' || names[names.length - 1] === 'OP_EQUAL')) {
      const k = t[t.length - 2].num !== undefined ? t[t.length - 2].num : null;
      const keys = t.filter(x => x.data && x.data.length === 32).map(x => Bytes.bytesToHex(x.data));
      return { type: 'tapscript_multisig', description: `Tapscript ${k}-of-${keys.length} multisig`, m: k, n: keys.length, pubkeys: keys, features, asm: asm(script) };
    }
    const sigs = names.filter(n => /CHECKSIG/.test(n)).length;
    return { type: 'custom', description: `Custom script (${t.length} ops, ${sigs} signature check${sigs === 1 ? '' : 's'})`, features, asm: asm(script) };
  }

  /** Human-readable meaning for a script type. */
  const TYPE_LABELS = {
    p2pkh: 'P2PKH', p2sh: 'P2SH', p2wpkh: 'P2WPKH', p2wsh: 'P2WSH', p2tr: 'P2TR', p2pk: 'P2PK', op_return: 'OP_RETURN',
    multisig: 'Multisig', witness_unknown: 'Witness v?', nonstandard: 'Non-standard', empty: 'Empty', custom: 'Custom',
    tapscript_pk: 'Tapscript key', tapscript_multisig: 'Tapscript multisig', unknown: 'Unknown',
  };

  function scriptHashes(script) {
    return { hash160: Bytes.bytesToHex(Crypto.hash160(script)), sha256: Bytes.bytesToHex(Crypto.sha256(script)) };
  }

  root.Script = { OPS, NETWORKS, TYPE_LABELS, disassemble, asm, classifyOutput, classifyInner, parseMultisig, isPubkey, isDERSig, isSchnorrSig, scriptHashes };
})(typeof window !== 'undefined' ? window : globalThis);
