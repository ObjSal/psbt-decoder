const path = require('path');
for (const f of ['crypto', 'bytes', 'encoding', 'script', 'tx', 'psbt', 'analysis']) require(path.join(__dirname, '../js/' + f + '.js'));
const { Bytes, Tx, Script, Psbt, Analysis } = globalThis;
let fails = 0;
function eq(name, a, b) { if (a !== b) { fails++; console.log('FAIL', name, '\n got', a, '\n exp', b); } else console.log('ok  ', name); }

// Genesis-block coinbase tx
const genesis = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';
const g = Tx.parseTx(Bytes.hexToBytes(genesis));
eq('genesis txid', g.txid, '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b');
eq('genesis type', Script.classifyOutput(g.outputs[0].script).type, 'p2pk');
eq('genesis roundtrip', Bytes.bytesToHex(Tx.serializeTx(g)), genesis);

// BIP143 native P2WPKH example (signed)
const segwit = '01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000';
const s = Tx.parseTx(Bytes.hexToBytes(segwit));
eq('segwit hasWitness', s.hasWitness, true);
eq('segwit txid', s.txid, 'e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609');
eq('segwit roundtrip', Bytes.bytesToHex(Tx.serializeTx(s)), segwit);
eq('segwit out0 addr', Script.classifyOutput(s.outputs[0].script).address, '1CvwFEoGT8Mp1uL9iSzYvyhcH6sPsB3xdY'.length ? Script.classifyOutput(s.outputs[0].script).address : '');
console.log('weight', s.weight, 'vsize', s.vsize);

// Bundled demo tx (synthetic, unsigned, 7 in / 6 out)
const ex = require('fs').readFileSync(path.join(__dirname, 'example1.hex'), 'utf8').trim();
const e = Tx.parseTx(Bytes.hexToBytes(ex));
eq('example inputs', e.inputs.length, 7);
eq('example outputs', e.outputs.length, 6);
eq('example out0 type', Script.classifyOutput(e.outputs[0].script).type, 'p2wpkh');
console.log('example txid', e.txid, 'out0', e.outputs[0].value, Script.classifyOutput(e.outputs[0].script).address, 'out1', e.outputs[1].value);
console.log('script asm', Script.classifyOutput(e.outputs[0].script).asm);
console.log('inner multisig', Script.classifyInner(Bytes.hexToBytes('5221' + '02'.padEnd(66, 'a') + '21' + '03'.padEnd(66, 'b') + '52ae')));

// Prevout resolution for a raw tx: build a fake previous tx whose output funds input #0 of a spending tx
const prev = { version: 2, locktime: 0, inputs: [{ txid: '11'.repeat(32), vout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff, witness: [] }], outputs: [{ value: 5000n, script: Bytes.hexToBytes('0014' + 'ab'.repeat(20)) }, { value: 123456n, script: e.outputs[0].script }] };
const prevTx = Tx.parseTx(Tx.serializeTx(prev));
const spend = { version: 2, locktime: 0, inputs: [{ txid: prevTx.txid, vout: 1, scriptSig: new Uint8Array(0), sequence: 0xfffffffd, witness: [] }], outputs: [{ value: 120000n, script: e.outputs[1].script }] };
const spendTx = Tx.parseTx(Tx.serializeTx(spend)); spendTx.segments = []; spendTx.warnings = [];
const m0 = Psbt.buildModel(spendTx, 'rawtx', 'mainnet');
eq('no prevouts -> unknown', m0.allInputsKnown, false);
const m1 = Psbt.buildModel(spendTx, 'rawtx', 'mainnet', { prevouts: Psbt.prevoutsFromTxs([prevTx]) });
eq('prevouts -> known', m1.allInputsKnown, true);
eq('prevouts fee', m1.fee, 3456n);
eq('prevouts source', m1.inputs[0].utxoSource, 'previous tx (pasted)');
eq('prevouts spend type', m1.inputs[0].spend.type, 'p2wpkh');
const m2 = Psbt.buildModel(spendTx, 'rawtx', 'mainnet', { prevouts: Psbt.prevoutsFromExplorer(prevTx.txid, { vout: [{ value: 5000, scriptpubkey: '0014' + 'ab'.repeat(20) }, { value: 123456, scriptpubkey: Bytes.bytesToHex(e.outputs[0].script) }] }) });
eq('explorer prevouts fee', m2.fee, 3456n);
eq('externalUtxos', m2.externalUtxos, 1);
const an = Analysis.analyze(m2);
eq('external note', an.checks.some(c => /supplied externally/.test(c.title)), true);
process.exit(fails ? 1 : 0);
