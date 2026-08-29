const path = require('path');
for (const f of ['crypto', 'bytes', 'encoding', 'script', 'tx', 'psbt', 'analysis']) require(path.join(__dirname, '../js/' + f + '.js'));
const { Bytes, Tx, Psbt, Analysis } = globalThis;
const fx = require('./fixtures.json');
let fails = 0;
function eq(name, a, b) { if (a !== b) { fails++; console.log('FAIL', name, '\n got', a, '\n exp', b); } else console.log('ok  ', name); }
function run(name) {
  const bytes = Bytes.base64ToBytes(fx[name]);
  const m = Psbt.buildModel(Psbt.parsePsbt(bytes), 'psbt', 'mainnet');
  const a = Analysis.analyze(m);
  console.log(`\n== ${name}: status=${m.status} verdict=${a.verdict} fee=${m.fee} in0=${m.inputs[0].spend.label} [${m.inputs[0].have}/${m.inputs[0].need}]`);
  for (const c of a.checks) if (c.level !== 'info') console.log('   ', c.level.padEnd(6), c.title);
  return { m, a };
}
let r = run('p2wpkh_unsigned'); eq('unsigned status', r.m.status, 'unsigned'); eq('change', r.m.outputs[1].isChange, true); eq('fee', r.m.fee, 1500n);
r = run('p2wpkh_signed'); eq('signed status', r.m.status, 'signed'); eq('sighash', r.m.inputs[0].signatures[0].sighash, 1);
r = run('p2wpkh_finalized'); eq('finalized status', r.m.status, 'finalized'); eq('final txid', r.m.finalTx && r.m.finalTx.txid, fx.p2wpkh_final_txid); eq('final hex', r.m.finalTx && r.m.finalTx.hex, fx.p2wpkh_final_tx);
r = run('multisig_unsigned'); eq('ms type', r.m.inputs[0].spend.type, 'p2wsh'); eq('ms need', r.m.inputs[0].need, 2); eq('xpubs', r.m.psbt.global.xpubs.length, 3);
r = run('multisig_partial'); eq('partial status', r.m.status, 'partial'); eq('have', r.m.inputs[0].have, 1); eq('out p2tr', r.m.outputs[0].type, 'p2tr');
r = run('taproot_unsigned'); eq('tr type', r.m.inputs[0].spend.type, 'p2tr'); eq('opreturn', r.m.outputs[0].type, 'op_return'); eq('opreturn text', r.m.outputs[0].spkClass.dataText, 'hello taproot');
r = run('taproot_signed'); eq('tr signed (embit finalizes key-path)', r.m.status, 'finalized'); eq('tr sig kind', r.m.inputs[0].rawSignatures[0].kind, 'schnorr'); eq('tr sighash default', r.m.inputs[0].rawSignatures[0].sighash, 0);
r = run('trap_hugefee_sighashnone'); eq('trap verdict', r.a.verdict, 'danger'); eq('trap has NONE', r.a.checks.some(c => /SIGHASH_NONE/.test(c.title)), true); eq('trap fee', r.a.checks.some(c => /Absurdly high fee/.test(c.title)), true);
r = run('no_utxo_info'); eq('noutxo verdict', r.a.verdict, 'danger'); eq('noutxo msg', r.a.checks.some(c => /amounts unknown/.test(c.title)), true);
process.exit(fails ? 1 : 0);
