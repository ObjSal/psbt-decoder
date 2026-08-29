const path = require('path');
for (const f of ['crypto', 'bytes', 'encoding', 'script', 'tx', 'psbt', 'analysis']) require(path.join(__dirname, '../js/' + f + '.js'));
const { Bytes, Tx, Script, Psbt, Analysis, Crypto } = globalThis;
let fails = 0;
function eq(name, a, b) { if (a !== b) { fails++; console.log('FAIL', name, '\n got', a, '\n exp', b); } else console.log('ok  ', name); }

// Build a PSBT v0 from the example tx with synthetic witness_utxo for every input
const ex = require('fs').readFileSync(path.join(__dirname, 'example1.hex'), 'utf8').trim();
const txBytes = Bytes.hexToBytes(ex);
const tx = Tx.parseTx(txBytes);
function kv(type, key, value) { const k = Bytes.concat(Uint8Array.of(type), key); return Bytes.concat(Bytes.varintBytes(k.length), k, Bytes.varintBytes(value.length), value); }
const parts = [Uint8Array.from(Psbt.MAGIC), kv(0, new Uint8Array(0), txBytes), Uint8Array.of(0)];
const nIn = BigInt(tx.inputs.length);
const perIn = (tx.outputs.reduce((a, o) => a + o.value, 0n) + 50000n) / nIn; // ~ fee 50k sats
const fp = Bytes.hexToBytes('deadbeef');
tx.inputs.forEach((i, k) => {
  const spk = Bytes.hexToBytes('0014' + 'ab'.repeat(20));
  const wu = Bytes.concat(Bytes.u64le(perIn), Bytes.varintBytes(spk.length), spk);
  const pub = Bytes.hexToBytes('02' + k.toString(16).padStart(2, '0').repeat(32));
  const deriv = Bytes.concat(fp, Bytes.u32le(0x80000054), Bytes.u32le(0x80000000), Bytes.u32le(0x80000000), Bytes.u32le(0), Bytes.u32le(k));
  parts.push(kv(1, new Uint8Array(0), wu), kv(6, pub, deriv));
  if (k === 0) parts.push(kv(3, new Uint8Array(0), Bytes.u32le(1)));
  parts.push(Uint8Array.of(0));
});
tx.outputs.forEach((o, k) => {
  if (k === 0) { const pub = Bytes.hexToBytes('03' + 'cd'.repeat(32)); parts.push(kv(2, pub, Bytes.concat(fp, Bytes.u32le(0x80000054), Bytes.u32le(0x80000000), Bytes.u32le(0x80000000), Bytes.u32le(1), Bytes.u32le(7)))); }
  parts.push(Uint8Array.of(0));
});
const psbtBytes = Bytes.concat(...parts);
const parsed = Psbt.parsePsbt(psbtBytes);
eq('psbt inputs', parsed.inputs.length, tx.inputs.length);
const model = Psbt.buildModel(parsed, 'psbt', 'mainnet');
eq('fee', model.fee, perIn * nIn - tx.outputs.reduce((a, o) => a + o.value, 0n));
eq('status', model.status, 'unsigned');
eq('change detected', model.outputs[0].isChange, true);
eq('spend type', model.inputs[0].spend.type, 'p2wpkh');
const a = Analysis.analyze(model);
console.log('verdict', a.verdict, a.verdictTitle);
for (const c of a.checks) console.log(' ', c.level.padEnd(6), c.title, '—', c.detail.slice(0, 100));
console.log('segments', model.segments.length, 'estVsize', model.estimatedVsize);

// Raw tx model
const rawModel = Psbt.buildModel(Tx.parseTx(txBytes, { segments: [] }), 'rawtx', 'mainnet');
rawModel.segments = [];
eq('raw status', rawModel.status, 'unsigned');
const ra = Analysis.analyze(rawModel);
console.log('raw verdict', ra.verdict);
for (const c of ra.checks) console.log(' ', c.level.padEnd(6), c.title);

// BIP174 test vector (finalized-ish, with partial sigs) — must parse without throwing
const vec = 'cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9pbzfGEi97/fjNXpH3EGpfvFklUbeTxhb3BPNIhSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/2lvN8YSL3v9+M1ekfcQal+8WSVRt5PGFvcE80iBDZDGpPAAAAgAAAAIABAACAAQMEAQAAAAABASAAwusLAAAAABepFLPhCpfeZ2XuCbFmVvv+fjwHhDX5hwEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAAQMEAQAAAAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA';
try {
  const p = Psbt.parsePsbt(Bytes.base64ToBytes(vec));
  const m = Psbt.buildModel(p, 'psbt', 'testnet');
  eq('vec inputs', m.inputs.length, 2);
  console.log('vec in0', m.inputs[0].spend.label, m.inputs[0].status, m.inputs[0].address, 'fee', m.fee, 'utxoSrc', m.inputs.map(i => i.utxoSource));
  console.log('vec in1', m.inputs[1].spend.label);
  console.log('vec outs', m.outputs.map(o => [o.address, o.isChange]));
  const va = Analysis.analyze(m);
  console.log('vec verdict', va.verdict);
  for (const c of va.checks) console.log(' ', c.level.padEnd(6), c.title);
} catch (e) { console.log('vector parse error (vector may be misremembered):', e.message); }
process.exit(fails ? 1 : 0);
