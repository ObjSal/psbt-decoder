// Raw Bitcoin transaction parsing / serialization (legacy + SegWit).
(function (root) {
  'use strict';
  const { Crypto, Bytes } = root;
  const { Reader } = Bytes;

  /**
   * Parse a raw transaction. Records segments (annotated hex) into opts.segments if given.
   * @returns tx {version, inputs, outputs, locktime, hasWitness, size, weight, vsize, txid, wtxid, hex}
   */
  function parseTx(bytes, opts = {}) {
    const r = new Reader(bytes, 0, opts.segments || [], opts.base || 0);
    const tx = { inputs: [], outputs: [], hasWitness: false };
    tx.version = r.seg('Version', 'version', () => r.i32());

    // SegWit marker/flag detection
    let hasWitness = false;
    if (r.remaining >= 2 && bytes[r.pos] === 0x00 && bytes[r.pos + 1] === 0x01) {
      // Could be a legacy tx with 0 inputs (invalid anyway) — treat as segwit
      hasWitness = true;
      r.seg('SegWit marker', 'marker', () => r.u8());
      r.seg('SegWit flag', 'marker', () => r.u8());
    }
    const vin = r.seg('Input count', 'count', () => r.varint());
    if (vin > 100000) throw new Error('Unreasonable input count');
    for (let i = 0; i < vin; i++) {
      const inp = { index: i };
      inp.txid = r.seg(`Input #${i} prev txid`, 'in-txid', () => Bytes.bytesToHex(Bytes.reverse(r.bytes_(32))));
      inp.vout = r.seg(`Input #${i} prev vout`, 'in-vout', () => r.u32());
      const slen = r.seg(`Input #${i} scriptSig length`, 'len', () => r.varint());
      inp.scriptSig = r.seg(`Input #${i} scriptSig`, 'in-script', () => r.bytes_(slen));
      inp.sequence = r.seg(`Input #${i} sequence`, 'in-seq', () => r.u32());
      inp.witness = [];
      tx.inputs.push(inp);
    }
    const vout = r.seg('Output count', 'count', () => r.varint());
    if (vout > 100000) throw new Error('Unreasonable output count');
    for (let i = 0; i < vout; i++) {
      const out = { index: i };
      out.value = r.seg(`Output #${i} value`, 'out-value', () => r.u64());
      const slen = r.seg(`Output #${i} scriptPubKey length`, 'len', () => r.varint());
      out.script = r.seg(`Output #${i} scriptPubKey`, 'out-script', () => r.bytes_(slen));
      tx.outputs.push(out);
    }
    const witnessStart = r.pos;
    if (hasWitness) {
      for (let i = 0; i < vin; i++) {
        const n = r.seg(`Input #${i} witness item count`, 'count', () => r.varint());
        if (n > 10000) throw new Error('Unreasonable witness item count');
        for (let j = 0; j < n; j++) {
          const len = r.seg(`Input #${i} witness[${j}] length`, 'len', () => r.varint());
          tx.inputs[i].witness.push(r.seg(`Input #${i} witness[${j}]`, 'witness', () => r.bytes_(len)));
        }
      }
    }
    const witnessEnd = r.pos;
    tx.locktime = r.seg('Locktime', 'locktime', () => r.u32());
    if (!r.eof) throw new Error(`Trailing ${r.remaining} byte(s) after transaction`);

    tx.hasWitness = hasWitness;
    tx.bytes = bytes;
    tx.hex = Bytes.bytesToHex(bytes);
    tx.size = bytes.length;
    const stripped = serializeTx(tx, false);
    tx.strippedSize = stripped.length;
    tx.weight = hasWitness ? stripped.length * 3 + bytes.length : bytes.length * 4;
    tx.vsize = Math.ceil(tx.weight / 4);
    tx.txid = Bytes.bytesToHex(Bytes.reverse(Crypto.hash256(stripped)));
    tx.wtxid = hasWitness ? Bytes.bytesToHex(Bytes.reverse(Crypto.hash256(bytes))) : tx.txid;
    tx.witnessRange = hasWitness ? [witnessStart, witnessEnd] : null;
    return tx;
  }

  function serializeTx(tx, withWitness = true) {
    const parts = [];
    parts.push(Bytes.u32le(tx.version >>> 0));
    const useWitness = withWitness && tx.inputs.some(i => i.witness && i.witness.length);
    if (useWitness) parts.push(Uint8Array.of(0, 1));
    parts.push(Bytes.varintBytes(tx.inputs.length));
    for (const i of tx.inputs) {
      parts.push(Bytes.reverse(Bytes.hexToBytes(i.txid)));
      parts.push(Bytes.u32le(i.vout));
      parts.push(Bytes.varintBytes(i.scriptSig.length), i.scriptSig);
      parts.push(Bytes.u32le(i.sequence));
    }
    parts.push(Bytes.varintBytes(tx.outputs.length));
    for (const o of tx.outputs) {
      parts.push(Bytes.u64le(o.value));
      parts.push(Bytes.varintBytes(o.script.length), o.script);
    }
    if (useWitness) {
      for (const i of tx.inputs) {
        parts.push(Bytes.varintBytes(i.witness.length));
        for (const w of i.witness) parts.push(Bytes.varintBytes(w.length), w);
      }
    }
    parts.push(Bytes.u32le(tx.locktime));
    return Bytes.concat(...parts);
  }

  function parseWitnessStack(bytes) {
    const r = new Reader(bytes);
    const n = r.varint();
    const items = [];
    for (let i = 0; i < n; i++) items.push(r.varbytes());
    if (!r.eof) throw new Error('Trailing bytes in witness stack');
    return items;
  }

  root.Tx = { parseTx, serializeTx, parseWitnessStack };
})(typeof window !== 'undefined' ? window : globalThis);
