// PSBT (BIP174 v0 / BIP370 v2) parsing into a normalized model shared with raw transactions.
(function (root) {
  'use strict';
  const { Crypto, Bytes, Encoding, Script, Tx } = root;
  const { Reader } = Bytes;

  const MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff];

  const GLOBAL_TYPES = {
    0x00: 'PSBT_GLOBAL_UNSIGNED_TX', 0x01: 'PSBT_GLOBAL_XPUB', 0x02: 'PSBT_GLOBAL_TX_VERSION', 0x03: 'PSBT_GLOBAL_FALLBACK_LOCKTIME',
    0x04: 'PSBT_GLOBAL_INPUT_COUNT', 0x05: 'PSBT_GLOBAL_OUTPUT_COUNT', 0x06: 'PSBT_GLOBAL_TX_MODIFIABLE', 0xfb: 'PSBT_GLOBAL_VERSION', 0xfc: 'PSBT_GLOBAL_PROPRIETARY',
  };
  const INPUT_TYPES = {
    0x00: 'PSBT_IN_NON_WITNESS_UTXO', 0x01: 'PSBT_IN_WITNESS_UTXO', 0x02: 'PSBT_IN_PARTIAL_SIG', 0x03: 'PSBT_IN_SIGHASH_TYPE',
    0x04: 'PSBT_IN_REDEEM_SCRIPT', 0x05: 'PSBT_IN_WITNESS_SCRIPT', 0x06: 'PSBT_IN_BIP32_DERIVATION', 0x07: 'PSBT_IN_FINAL_SCRIPTSIG',
    0x08: 'PSBT_IN_FINAL_SCRIPTWITNESS', 0x09: 'PSBT_IN_POR_COMMITMENT', 0x0a: 'PSBT_IN_RIPEMD160', 0x0b: 'PSBT_IN_SHA256',
    0x0c: 'PSBT_IN_HASH160', 0x0d: 'PSBT_IN_HASH256', 0x0e: 'PSBT_IN_PREVIOUS_TXID', 0x0f: 'PSBT_IN_OUTPUT_INDEX', 0x10: 'PSBT_IN_SEQUENCE',
    0x11: 'PSBT_IN_REQUIRED_TIME_LOCKTIME', 0x12: 'PSBT_IN_REQUIRED_HEIGHT_LOCKTIME', 0x13: 'PSBT_IN_TAP_KEY_SIG', 0x14: 'PSBT_IN_TAP_SCRIPT_SIG',
    0x15: 'PSBT_IN_TAP_LEAF_SCRIPT', 0x16: 'PSBT_IN_TAP_BIP32_DERIVATION', 0x17: 'PSBT_IN_TAP_INTERNAL_KEY', 0x18: 'PSBT_IN_TAP_MERKLE_ROOT',
    0x19: 'PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS', 0x1a: 'PSBT_IN_MUSIG2_PUB_NONCE', 0x1b: 'PSBT_IN_MUSIG2_PARTIAL_SIG', 0xfc: 'PSBT_IN_PROPRIETARY',
  };
  const OUTPUT_TYPES = {
    0x00: 'PSBT_OUT_REDEEM_SCRIPT', 0x01: 'PSBT_OUT_WITNESS_SCRIPT', 0x02: 'PSBT_OUT_BIP32_DERIVATION', 0x03: 'PSBT_OUT_AMOUNT',
    0x04: 'PSBT_OUT_SCRIPT', 0x05: 'PSBT_OUT_TAP_INTERNAL_KEY', 0x06: 'PSBT_OUT_TAP_TREE', 0x07: 'PSBT_OUT_TAP_BIP32_DERIVATION',
    0x08: 'PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS', 0xfc: 'PSBT_OUT_PROPRIETARY',
  };

  const SIGHASH_NAMES = { 0: 'SIGHASH_DEFAULT', 1: 'SIGHASH_ALL', 2: 'SIGHASH_NONE', 3: 'SIGHASH_SINGLE', 0x81: 'SIGHASH_ALL|ANYONECANPAY', 0x82: 'SIGHASH_NONE|ANYONECANPAY', 0x83: 'SIGHASH_SINGLE|ANYONECANPAY' };
  const sighashName = (t) => SIGHASH_NAMES[t] || `unknown (0x${t.toString(16)})`;

  function isPsbt(bytes) { return bytes.length >= 5 && MAGIC.every((b, i) => bytes[i] === b); }

  /** Read one key-value map. Returns array of {type, typeName, key(Uint8Array keydata), value, raw} */
  function readMap(r, typeNames, scope, idx) {
    const entries = [];
    const seen = new Set();
    const label = scope === 'global' ? 'Global' : `${scope === 'input' ? 'Input' : 'Output'} #${idx}`;
    for (;;) {
      if (r.eof) throw new Error(`${label} map is not terminated (missing 0x00 separator)`);
      const keyStart = r.pos;
      const keyLen = r.varint();
      if (keyLen === 0) {
        r.segments.push({ start: keyStart + r.base, end: r.pos + r.base, label: `${label} map separator`, cls: 'sep' });
        break;
      }
      const keyBytes = r.bytes_(keyLen);
      const kr = new Reader(keyBytes);
      const type = kr.varint();
      const keyData = keyBytes.slice(kr.pos);
      const typeName = typeNames[type] || `UNKNOWN_0x${type.toString(16)}`;
      const dedupe = Bytes.bytesToHex(keyBytes);
      if (seen.has(dedupe)) throw new Error(`${label}: duplicate key ${typeName} (invalid PSBT)`);
      seen.add(dedupe);
      r.segments.push({ start: keyStart + r.base, end: r.pos + r.base, label: `${label} key: ${typeName}`, cls: 'psbt-key', value: keyData.length ? Bytes.bytesToHex(keyData) : '' });
      const valStart = r.pos;
      const value = r.varbytes();
      r.segments.push({ start: valStart + r.base, end: r.pos + r.base, label: `${label} value: ${typeName}`, cls: 'psbt-val', value: Bytes.bytesToHex(value), valueStart: valStart + (r.pos - valStart - value.length) + r.base });
      entries.push({ type, typeName, keyData, value, valueOffset: r.pos - value.length + r.base });
    }
    return entries;
  }

  const u32 = (b) => { if (b.length !== 4) throw new Error('expected 4 bytes'); return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true); };
  const u64 = (b) => { if (b.length !== 8) throw new Error('expected 8 bytes'); return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, true); };
  const i64 = (b) => { if (b.length !== 8) throw new Error('expected 8 bytes'); return new DataView(b.buffer, b.byteOffset, 8).getBigInt64(0, true); };
  const hex = Bytes.bytesToHex;

  function parseProprietary(keyData) {
    const r = new Reader(keyData);
    const id = r.varbytes();
    const subtype = r.varint();
    const data = r.bytes_(r.remaining);
    let idText = null;
    try { idText = new TextDecoder('utf-8', { fatal: true }).decode(id); } catch (e) { /* */ }
    return { identifier: hex(id), identifierText: idText, subtype, keyData: hex(data) };
  }

  function parsePsbt(bytes) {
    if (!isPsbt(bytes)) throw new Error('Missing PSBT magic bytes (psbt\\xff)');
    const segments = [];
    const r = new Reader(bytes, 0, segments, 0);
    r.seg('PSBT magic', 'magic', () => r.bytes_(5));

    const warnings = [];
    const psbt = { version: 0, global: { xpubs: [], unknown: [], proprietary: [] }, inputs: [], outputs: [], segments, warnings, bytes };
    const g = psbt.global;
    const gEntries = readMap(r, GLOBAL_TYPES, 'global');
    for (const e of gEntries) {
      switch (e.type) {
        case 0x00: {
          const txSegs = [];
          g.unsignedTx = Tx.parseTx(e.value, { segments: txSegs, base: e.valueOffset });
          segments.push(...txSegs.map(s => ({ ...s, cls: 'tx-' + s.cls, label: 'Unsigned tx: ' + s.label })));
          if (g.unsignedTx.inputs.some(i => i.scriptSig.length || i.witness.length)) warnings.push('Unsigned transaction has non-empty scriptSig/witness (invalid per BIP174)');
          break;
        }
        case 0x01: {
          const x = Encoding.decodeXpub(e.keyData);
          const d = Encoding.parseDerivation(e.value);
          g.xpubs.push({ ...x, masterFingerprint: d.fingerprint, path: d.pathStr, pathArr: d.path });
          break;
        }
        case 0x02: g.txVersion = new DataView(e.value.buffer, e.value.byteOffset, 4).getInt32(0, true); break;
        case 0x03: g.fallbackLocktime = u32(e.value); break;
        case 0x04: g.inputCount = new Reader(e.value).varint(); break;
        case 0x05: g.outputCount = new Reader(e.value).varint(); break;
        case 0x06: g.txModifiable = e.value[0]; break;
        case 0xfb: psbt.version = u32(e.value); break;
        case 0xfc: g.proprietary.push({ ...parseProprietary(e.keyData), value: hex(e.value) }); break;
        default: g.unknown.push({ type: e.type, key: hex(e.keyData), value: hex(e.value) });
      }
    }
    if (psbt.version === 0 && !g.unsignedTx) throw new Error('PSBT v0 is missing PSBT_GLOBAL_UNSIGNED_TX');
    if (psbt.version === 2 && g.unsignedTx) warnings.push('PSBT v2 must not contain PSBT_GLOBAL_UNSIGNED_TX');
    if (psbt.version !== 0 && psbt.version !== 2) warnings.push(`Unusual PSBT version ${psbt.version}`);

    const nIn = g.unsignedTx ? g.unsignedTx.inputs.length : g.inputCount;
    const nOut = g.unsignedTx ? g.unsignedTx.outputs.length : g.outputCount;
    if (nIn === undefined || nOut === undefined) throw new Error('Cannot determine input/output count');

    for (let i = 0; i < nIn; i++) psbt.inputs.push(parseInputMap(readMap(r, INPUT_TYPES, 'input', i), i, warnings));
    for (let i = 0; i < nOut; i++) psbt.outputs.push(parseOutputMap(readMap(r, OUTPUT_TYPES, 'output', i), i, warnings));
    if (!r.eof) warnings.push(`${r.remaining} trailing byte(s) after the last output map`);
    return psbt;
  }

  function parseInputMap(entries, index, warnings) {
    const inp = { index, partialSigs: [], bip32: [], preimages: [], tapScriptSigs: [], tapLeafScripts: [], tapBip32: [], unknown: [], proprietary: [], raw: entries };
    for (const e of entries) {
      try {
        switch (e.type) {
          case 0x00: inp.nonWitnessUtxo = Tx.parseTx(e.value); break;
          case 0x01: { const r = new Reader(e.value); inp.witnessUtxo = { value: r.u64(), script: r.varbytes() }; if (!r.eof) warnings.push(`Input #${index}: trailing bytes in witness_utxo`); break; }
          case 0x02: inp.partialSigs.push({ pubkey: hex(e.keyData), sig: hex(e.value), sighash: e.value[e.value.length - 1] }); break;
          case 0x03: inp.sighashType = u32(e.value); break;
          case 0x04: inp.redeemScript = e.value; break;
          case 0x05: inp.witnessScript = e.value; break;
          case 0x06: inp.bip32.push({ pubkey: hex(e.keyData), ...Encoding.parseDerivation(e.value) }); break;
          case 0x07: inp.finalScriptSig = e.value; break;
          case 0x08: inp.finalScriptWitness = Tx.parseWitnessStack(e.value); break;
          case 0x09: inp.porCommitment = new TextDecoder().decode(e.value); break;
          case 0x0a: inp.preimages.push({ algo: 'RIPEMD160', hash: hex(e.keyData), preimage: hex(e.value) }); break;
          case 0x0b: inp.preimages.push({ algo: 'SHA256', hash: hex(e.keyData), preimage: hex(e.value) }); break;
          case 0x0c: inp.preimages.push({ algo: 'HASH160', hash: hex(e.keyData), preimage: hex(e.value) }); break;
          case 0x0d: inp.preimages.push({ algo: 'HASH256', hash: hex(e.keyData), preimage: hex(e.value) }); break;
          case 0x0e: inp.previousTxid = hex(Bytes.reverse(e.value)); break;
          case 0x0f: inp.outputIndex = u32(e.value); break;
          case 0x10: inp.sequence = u32(e.value); break;
          case 0x11: inp.requiredTimeLocktime = u32(e.value); break;
          case 0x12: inp.requiredHeightLocktime = u32(e.value); break;
          case 0x13: inp.tapKeySig = { sig: hex(e.value), sighash: e.value.length === 65 ? e.value[64] : 0 }; break;
          case 0x14: inp.tapScriptSigs.push({ xonly: hex(e.keyData.slice(0, 32)), leafHash: hex(e.keyData.slice(32, 64)), sig: hex(e.value), sighash: e.value.length === 65 ? e.value[64] : 0 }); break;
          case 0x15: inp.tapLeafScripts.push({ controlBlock: hex(e.keyData), script: e.value.slice(0, -1), leafVersion: e.value[e.value.length - 1] }); break;
          case 0x16: {
            const r = new Reader(e.value); const n = r.varint(); const hashes = [];
            for (let k = 0; k < n; k++) hashes.push(hex(r.bytes_(32)));
            inp.tapBip32.push({ xonly: hex(e.keyData), leafHashes: hashes, ...Encoding.parseDerivation(e.value.slice(r.pos)) });
            break;
          }
          case 0x17: inp.tapInternalKey = hex(e.value); break;
          case 0x18: inp.tapMerkleRoot = hex(e.value); break;
          case 0xfc: inp.proprietary.push({ ...parseProprietary(e.keyData), value: hex(e.value) }); break;
          default: inp.unknown.push({ type: e.type, typeName: e.typeName, key: hex(e.keyData), value: hex(e.value) });
        }
      } catch (err) {
        warnings.push(`Input #${index}: could not parse ${e.typeName}: ${err.message}`);
      }
    }
    return inp;
  }

  function parseOutputMap(entries, index, warnings) {
    const out = { index, bip32: [], tapBip32: [], unknown: [], proprietary: [], raw: entries };
    for (const e of entries) {
      try {
        switch (e.type) {
          case 0x00: out.redeemScript = e.value; break;
          case 0x01: out.witnessScript = e.value; break;
          case 0x02: out.bip32.push({ pubkey: hex(e.keyData), ...Encoding.parseDerivation(e.value) }); break;
          case 0x03: out.amount = i64(e.value); break;
          case 0x04: out.script = e.value; break;
          case 0x05: out.tapInternalKey = hex(e.value); break;
          case 0x06: out.tapTree = hex(e.value); break;
          case 0x07: {
            const r = new Reader(e.value); const n = r.varint(); const hashes = [];
            for (let k = 0; k < n; k++) hashes.push(hex(r.bytes_(32)));
            out.tapBip32.push({ xonly: hex(e.keyData), leafHashes: hashes, ...Encoding.parseDerivation(e.value.slice(r.pos)) });
            break;
          }
          case 0xfc: out.proprietary.push({ ...parseProprietary(e.keyData), value: hex(e.value) }); break;
          default: out.unknown.push({ type: e.type, typeName: e.typeName, key: hex(e.keyData), value: hex(e.value) });
        }
      } catch (err) {
        warnings.push(`Output #${index}: could not parse ${e.typeName}: ${err.message}`);
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------------------
  // Normalized model (shared by PSBT and raw tx) used by analysis + UI
  // ---------------------------------------------------------------------------------------

  /** Extract signature-like pushes and their sighash bytes from a scriptSig / witness stack. */
  function findSignatures(items) {
    const sigs = [];
    for (const d of items) {
      if (Script.isDERSig(d)) sigs.push({ kind: 'ecdsa', sig: hex(d), sighash: d[d.length - 1] });
      else if (d.length === 64 || d.length === 65) {
        // could be a schnorr sig (or a 64/65-byte something else); treat as schnorr only if not a pubkey
        if (!Script.isPubkey(d)) sigs.push({ kind: 'schnorr', sig: hex(d), sighash: d.length === 65 ? d[64] : 0 });
      }
    }
    return sigs;
  }

  /** Work out how an input is going to be spent, from scriptPubKey + redeem/witness scripts. */
  function resolveSpendType(spkClass, redeemScript, witnessScript, tapLeafScripts, network) {
    const info = { type: spkClass ? spkClass.type : 'unknown', label: '', description: '', m: 1, n: 1, segwit: false, taproot: false, layers: [] };
    if (!spkClass) { info.label = 'Unknown (no UTXO info)'; info.description = 'The previous output script is not available, so the spend type cannot be determined.'; info.m = null; return info; }
    info.layers.push(spkClass);
    let t = spkClass.type;
    if (t === 'p2sh') {
      if (redeemScript) {
        const rs = Script.classifyInner(redeemScript, network);
        info.layers.push(rs);
        if (rs.type === 'p2wpkh') { info.type = 'p2sh-p2wpkh'; info.label = 'P2SH-P2WPKH (wrapped SegWit)'; info.segwit = true; }
        else if (rs.type === 'p2wsh') {
          info.segwit = true;
          if (witnessScript) {
            const ws = Script.classifyInner(witnessScript, network);
            info.layers.push(ws);
            info.type = 'p2sh-p2wsh'; info.label = `P2SH-P2WSH: ${ws.description}`; if (ws.m) { info.m = ws.m; info.n = ws.n; }
          } else { info.type = 'p2sh-p2wsh'; info.label = 'P2SH-P2WSH (witness script missing)'; info.m = null; }
        } else { info.type = 'p2sh'; info.label = `P2SH: ${rs.description}`; if (rs.m) { info.m = rs.m; info.n = rs.n; } }
      } else { info.label = 'P2SH (redeem script missing)'; info.m = null; }
    } else if (t === 'p2wsh') {
      info.segwit = true;
      if (witnessScript) { const ws = Script.classifyInner(witnessScript, network); info.layers.push(ws); info.label = `P2WSH: ${ws.description}`; if (ws.m) { info.m = ws.m; info.n = ws.n; } }
      else { info.label = 'P2WSH (witness script missing)'; info.m = null; }
    } else if (t === 'p2wpkh') { info.segwit = true; info.label = 'P2WPKH (native SegWit)'; }
    else if (t === 'p2tr') {
      info.segwit = true; info.taproot = true;
      if (tapLeafScripts && tapLeafScripts.length) { const ls = tapLeafScripts.map(l => Script.classifyInner(l.script, network)); info.layers.push(...ls); info.label = `P2TR script path: ${ls.map(l => l.description).join('; ')}`; const ms = ls.find(l => l.m); if (ms) { info.m = ms.m; info.n = ms.n; } }
      else info.label = 'P2TR key path (Taproot)';
    } else if (t === 'p2pkh') info.label = 'P2PKH (legacy)';
    else if (t === 'p2pk') info.label = 'P2PK (legacy bare key)';
    else if (t === 'multisig') { info.label = `Bare ${spkClass.m}-of-${spkClass.n} multisig`; info.m = spkClass.m; info.n = spkClass.n; }
    else info.label = spkClass.description;
    info.description = info.label;
    return info;
  }

  /** Estimated virtual size contribution of one input once fully signed. */
  function estimateInputVsize(spend) {
    switch (spend.type) {
      case 'p2pkh': return 148;
      case 'p2pk': return 114;
      case 'p2wpkh': return 68;
      case 'p2sh-p2wpkh': return 91;
      case 'p2tr': return spend.layers.length > 1 ? 41 + (65 * (spend.m || 1) + 100) / 4 : 57.5;
      case 'p2wsh': case 'p2sh-p2wsh': { const m = spend.m || 1, n = spend.n || 1; const wit = 1 + m * 73 + 3 + n * 34 + 2; return 41 + (spend.type === 'p2sh-p2wsh' ? 35 : 0) + wit / 4; }
      case 'p2sh': case 'multisig': { const m = spend.m || 1, n = spend.n || 1; return 41 + m * 73 + 3 + n * 34 + 2; }
      default: return 110;
    }
  }
  function estimateOutputVsize(script) { return 9 + script.length; }

  function buildModel(parsed, kind, network) {
    const model = { kind, network, inputs: [], outputs: [], warnings: parsed.warnings || [], segments: parsed.segments, bytes: parsed.bytes };
    let tx;
    if (kind === 'psbt') {
      model.psbt = parsed;
      model.psbtVersion = parsed.version;
      const g = parsed.global;
      if (g.unsignedTx) tx = g.unsignedTx;
      else {
        // PSBT v2: build tx from per-input/output fields
        tx = {
          version: g.txVersion !== undefined ? g.txVersion : 2, locktime: g.fallbackLocktime || 0, hasWitness: false,
          inputs: parsed.inputs.map((i, k) => ({ index: k, txid: i.previousTxid || '00'.repeat(32), vout: i.outputIndex || 0, sequence: i.sequence !== undefined ? i.sequence : 0xffffffff, scriptSig: new Uint8Array(0), witness: [] })),
          outputs: parsed.outputs.map((o, k) => ({ index: k, value: o.amount !== undefined ? o.amount : 0n, script: o.script || new Uint8Array(0) })),
        };
        const ser = Tx.serializeTx(tx, false);
        tx.bytes = ser; tx.hex = hex(ser); tx.size = ser.length; tx.strippedSize = ser.length; tx.weight = ser.length * 4; tx.vsize = ser.length; tx.txid = hex(Bytes.reverse(Crypto.hash256(ser))); tx.wtxid = tx.txid;
      }
    } else {
      tx = parsed;
    }
    model.tx = tx;

    const pIns = kind === 'psbt' ? parsed.inputs : tx.inputs.map(() => ({ partialSigs: [], bip32: [], preimages: [], tapScriptSigs: [], tapLeafScripts: [], tapBip32: [], unknown: [], proprietary: [] }));
    const pOuts = kind === 'psbt' ? parsed.outputs : tx.outputs.map(() => ({ bip32: [], tapBip32: [], unknown: [], proprietary: [] }));

    let estVsize = 10.5;
    const fingerprints = new Set();

    tx.inputs.forEach((txin, i) => {
      const p = pIns[i];
      const inp = { index: i, txid: txin.txid, vout: txin.vout, sequence: txin.sequence, psbt: p, problems: [] };
      // UTXO resolution
      let utxo = null, utxoSource = null;
      if (p.witnessUtxo) { utxo = { value: p.witnessUtxo.value, script: p.witnessUtxo.script }; utxoSource = 'witness_utxo'; }
      if (p.nonWitnessUtxo) {
        const prev = p.nonWitnessUtxo;
        if (prev.txid !== txin.txid) inp.problems.push({ level: 'danger', text: `non_witness_utxo txid ${prev.txid.slice(0, 16)}… does not match the input's prevout txid ${txin.txid.slice(0, 16)}…` });
        else if (txin.vout >= prev.outputs.length) inp.problems.push({ level: 'danger', text: `non_witness_utxo has only ${prev.outputs.length} outputs but vout is ${txin.vout}` });
        else {
          const o = prev.outputs[txin.vout];
          if (utxo) {
            if (utxo.value !== o.value || !Bytes.equal(utxo.script, o.script)) inp.problems.push({ level: 'danger', text: 'witness_utxo and non_witness_utxo disagree on amount/script' });
          }
          utxo = { value: o.value, script: o.script };
          utxoSource = utxoSource ? 'both' : 'non_witness_utxo';
        }
      }
      inp.utxo = utxo; inp.utxoSource = utxoSource;
      inp.value = utxo ? utxo.value : null;
      inp.spkClass = utxo ? Script.classifyOutput(utxo.script, network) : null;
      inp.address = inp.spkClass ? inp.spkClass.address : null;
      inp.spend = resolveSpendType(inp.spkClass, p.redeemScript, p.witnessScript, p.tapLeafScripts, network);

      // script hash consistency
      if (utxo && p.redeemScript && inp.spkClass.type === 'p2sh') {
        if (Script.scriptHashes(p.redeemScript).hash160 !== inp.spkClass.hash) inp.problems.push({ level: 'danger', text: 'redeem_script hash does not match the P2SH scriptPubKey' });
      }
      if (utxo && p.witnessScript) {
        const sh = Script.scriptHashes(p.witnessScript).sha256;
        let expect = null;
        if (inp.spkClass.type === 'p2wsh') expect = inp.spkClass.hash;
        else if (p.redeemScript) { const rs = Script.classifyOutput(p.redeemScript, network); if (rs.type === 'p2wsh') expect = rs.hash; }
        if (expect && sh !== expect) inp.problems.push({ level: 'danger', text: 'witness_script hash does not match the P2WSH program' });
      }
      if (utxoSource === 'witness_utxo' && inp.spkClass && !inp.spend.segwit) inp.problems.push({ level: 'warn', text: 'witness_utxo provided for a non-SegWit input (a full non_witness_utxo is required to sign legacy inputs safely)' });

      // signatures
      const sigs = [];
      for (const s of p.partialSigs) sigs.push({ kind: 'ecdsa', pubkey: s.pubkey, sig: s.sig, sighash: s.sighash });
      if (p.tapKeySig) sigs.push({ kind: 'schnorr', pubkey: p.tapInternalKey || null, sig: p.tapKeySig.sig, sighash: p.tapKeySig.sighash, tapKeyPath: true });
      for (const s of p.tapScriptSigs) sigs.push({ kind: 'schnorr', pubkey: s.xonly, sig: s.sig, sighash: s.sighash, leafHash: s.leafHash });
      const finalized = !!(p.finalScriptSig || p.finalScriptWitness);
      const rawSigs = kind === 'psbt'
        ? findSignatures([...(p.finalScriptWitness || []), ...(p.finalScriptSig ? Script.disassemble(p.finalScriptSig).filter(t => t.data).map(t => t.data) : [])])
        : findSignatures([...(txin.witness || []), ...Script.disassemble(txin.scriptSig).filter(t => t.data).map(t => t.data)]);
      inp.rawSignatures = rawSigs;
      const rawSigned = kind === 'rawtx' && (txin.scriptSig.length > 0 || (txin.witness && txin.witness.length > 0));
      inp.signatures = sigs;
      inp.finalized = finalized;
      inp.need = inp.spend.m;
      inp.have = finalized || rawSigned ? Math.max(rawSigs.length, inp.need || 1) : sigs.length;
      if (finalized) inp.status = 'finalized';
      else if (rawSigned) inp.status = rawSigs.length ? 'signed' : 'signed?';
      else if (sigs.length === 0) inp.status = 'unsigned';
      else if (inp.need !== null && sigs.length >= inp.need) inp.status = 'signed';
      else inp.status = 'partial';
      inp.sighashes = [...new Set([...sigs.map(s => s.sighash), ...rawSigs.map(s => s.sighash)])];
      if (p.sighashType !== undefined) inp.declaredSighash = p.sighashType;

      inp.scriptSig = kind === 'psbt' ? (p.finalScriptSig || null) : txin.scriptSig;
      inp.witness = kind === 'psbt' ? (p.finalScriptWitness || null) : txin.witness;
      inp.redeemScript = p.redeemScript || null;
      inp.witnessScript = p.witnessScript || null;
      // heuristically recover redeem/witness scripts from a signed raw tx for display
      if (kind === 'rawtx' && txin.scriptSig.length) {
        const pushes = Script.disassemble(txin.scriptSig).filter(t => t.data && t.data.length);
        const last = pushes[pushes.length - 1];
        if (last && last.data.length > 33 && !Script.isDERSig(last.data)) inp.redeemScript = last.data;
        else if (last && (last.data.length === 22 || last.data.length === 34) && (last.data[0] === 0x00) && pushes.length === 1) inp.redeemScript = last.data;
      }
      if (kind === 'rawtx' && txin.witness && txin.witness.length > 2) {
        const last = txin.witness[txin.witness.length - 1];
        if (!Script.isDERSig(last) && !Script.isPubkey(last) && last.length > 33) inp.witnessScript = last;
      }
      if (kind === 'rawtx' && !utxo) {
        // Infer spend type from scriptSig/witness shape
        const w = txin.witness || [];
        const ss = txin.scriptSig;
        let guess = null;
        if (ss.length === 0 && w.length === 2 && Script.isDERSig(w[0]) && Script.isPubkey(w[1])) guess = { type: 'p2wpkh', label: 'P2WPKH (inferred from witness)', segwit: true, m: 1, n: 1, layers: [] };
        else if (ss.length === 0 && w.length === 1 && (w[0].length === 64 || w[0].length === 65)) guess = { type: 'p2tr', label: 'P2TR key path (inferred from witness)', segwit: true, taproot: true, m: 1, n: 1, layers: [] };
        else if (ss.length === 23 && ss[0] === 0x16 && ss[1] === 0x00 && ss[2] === 0x14) guess = { type: 'p2sh-p2wpkh', label: 'P2SH-P2WPKH (inferred from scriptSig)', segwit: true, m: 1, n: 1, layers: [] };
        else if (ss.length === 0 && w.length > 2 && inp.witnessScript) { const ws = Script.classifyInner(inp.witnessScript, network); guess = { type: 'p2wsh', label: `P2WSH: ${ws.description} (inferred from witness)`, segwit: true, m: ws.m || 1, n: ws.n || 1, layers: [ws] }; }
        else if (ss.length && inp.redeemScript && inp.redeemScript.length > 34) { const rs = Script.classifyInner(inp.redeemScript, network); guess = { type: 'p2sh', label: `P2SH: ${rs.description} (inferred from scriptSig)`, segwit: false, m: rs.m || 1, n: rs.n || 1, layers: [rs] }; }
        else if (ss.length && w.length === 0) { const pushes = Script.disassemble(ss).filter(t => t.data); if (pushes.length === 2 && Script.isDERSig(pushes[0].data) && Script.isPubkey(pushes[1].data)) guess = { type: 'p2pkh', label: 'P2PKH (inferred from scriptSig)', segwit: false, m: 1, n: 1, layers: [] }; }
        if (guess) { guess.description = guess.label; guess.inferred = true; inp.spend = guess; inp.need = guess.m; if (inp.status === 'signed?') inp.status = 'signed'; }
        else { inp.spend.label = 'Unknown (raw transaction, no UTXO info)'; inp.spend.description = inp.spend.label; }
      }
      // fingerprints
      for (const d of [...p.bip32, ...p.tapBip32]) fingerprints.add(d.fingerprint);
      estVsize += estimateInputVsize(inp.spend);
      model.inputs.push(inp);
    });

    tx.outputs.forEach((txout, i) => {
      const p = pOuts[i];
      const out = { index: i, value: txout.value, script: txout.script, psbt: p, problems: [] };
      out.spkClass = Script.classifyOutput(txout.script, network);
      out.address = out.spkClass.address;
      out.type = out.spkClass.type;
      out.bip32 = [...p.bip32, ...p.tapBip32];
      out.isChange = out.bip32.some(d => fingerprints.has(d.fingerprint));
      out.hasDerivation = out.bip32.length > 0;
      out.redeemScript = p.redeemScript || null;
      out.witnessScript = p.witnessScript || null;
      if (p.redeemScript && out.spkClass.type === 'p2sh' && Script.scriptHashes(p.redeemScript).hash160 !== out.spkClass.hash) out.problems.push({ level: 'danger', text: 'Output redeem_script does not match its P2SH scriptPubKey' });
      if (p.witnessScript && out.spkClass.type === 'p2wsh' && Script.scriptHashes(p.witnessScript).sha256 !== out.spkClass.hash) out.problems.push({ level: 'danger', text: 'Output witness_script does not match its P2WSH scriptPubKey' });
      estVsize += estimateOutputVsize(txout.script);
      model.outputs.push(out);
    });

    model.fingerprints = [...fingerprints];
    model.estimatedVsize = Math.ceil(estVsize);
    model.totalOut = model.outputs.reduce((a, o) => a + o.value, 0n);
    model.allInputsKnown = model.inputs.length > 0 && model.inputs.every(i => i.value !== null);
    model.totalIn = model.allInputsKnown ? model.inputs.reduce((a, i) => a + i.value, 0n) : null;
    model.fee = model.allInputsKnown ? model.totalIn - model.totalOut : null;

    // Status roll-up
    const statuses = model.inputs.map(i => i.status);
    if (model.inputs.length === 0) model.status = 'empty';
    else if (statuses.every(s => s === 'finalized')) model.status = 'finalized';
    else if (kind === 'rawtx' && statuses.every(s => s === 'signed' || s === 'signed?')) model.status = 'signed';
    else if (kind === 'rawtx' && statuses.every(s => s === 'unsigned')) model.status = 'unsigned';
    else if (kind === 'rawtx') model.status = 'partial';
    else if (statuses.every(s => s === 'unsigned')) model.status = 'unsigned';
    else if (statuses.every(s => s === 'signed' || s === 'finalized')) model.status = 'signed';
    else model.status = 'partial';

    // Finalized tx extraction (PSBT)
    if (kind === 'psbt' && model.status === 'finalized') {
      try {
        const ftx = {
          version: tx.version, locktime: tx.locktime,
          inputs: tx.inputs.map((ti, k) => ({ txid: ti.txid, vout: ti.vout, sequence: ti.sequence, scriptSig: pIns[k].finalScriptSig || new Uint8Array(0), witness: pIns[k].finalScriptWitness || [] })),
          outputs: tx.outputs.map(o => ({ value: o.value, script: o.script })),
        };
        const ser = Tx.serializeTx(ftx, true);
        model.finalTx = Tx.parseTx(ser);
      } catch (e) { model.warnings.push('Could not extract final transaction: ' + e.message); }
    }
    if (kind === 'rawtx' && model.status === 'signed') model.finalTx = tx;
    model.actualVsize = model.finalTx ? model.finalTx.vsize : null;
    return model;
  }

  root.Psbt = { MAGIC, isPsbt, parsePsbt, buildModel, sighashName, SIGHASH_NAMES, GLOBAL_TYPES, INPUT_TYPES, OUTPUT_TYPES };
})(typeof window !== 'undefined' ? window : globalThis);
