// Script.classifyOutput on witness programs and look-alikes. Expected types and addresses are what
// Bitcoin Core v31.1.0 reports (bitcoin-tx -json -create outscript=0:0x<script>), plus the BIP173/BIP350 vectors.
const path = require('path');
for (const f of ['crypto', 'bytes', 'encoding', 'script', 'tx', 'psbt', 'analysis']) require(path.join(__dirname, '../js/' + f + '.js'));
const { Bytes, Script } = globalThis;
let fails = 0;
function eq(name, a, b) { if (a !== b) { fails++; console.log('FAIL', name, '\n got', a, '\n exp', b); } else console.log('ok  ', name); }
const cls = (hex) => Script.classifyOutput(Bytes.hexToBytes(hex), 'mainnet');

const h20 = '751e76e8199196d454941c45d1b3a323f1433bd6';
const h32 = '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262';
const tr = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

// Well-formed programs keep their types and addresses
for (const [name, hex, type, address] of [
  ['p2wpkh', '0014' + h20, 'p2wpkh', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'],
  ['p2wsh', '0020' + h32, 'p2wsh', 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'],
  ['p2tr', '5120' + tr, 'p2tr', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'],
  ['v2 16-byte program', '5210' + h20.slice(0, 32), 'witness_unknown', 'bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs'],
  ['v16 2-byte program', '6002751e', 'witness_unknown', 'bc1sw50qgdz25j'],
]) {
  const c = cls(hex);
  eq(name + ' type', c.type, type);
  eq(name + ' address', c.address, address);
}

// Look-alikes are not witness programs: nonstandard, no address
for (const [name, hex] of [
  ['v0 push of 20 announced, 10 present', '0014' + '5a'.repeat(10)],
  ['v0 push of 33 announced, 32 present', '0021' + h32],
  ['v1 push of 33 announced, 32 present', '5121' + tr],
  ['v0 21-byte program', '0015' + '5a'.repeat(21)],
  ['v0 program pushed with OP_PUSHDATA1', '004c14' + h20],
]) {
  const c = cls(hex);
  eq(name + ' type', c.type, 'nonstandard');
  eq(name + ' address', c.address, null);
  eq(name + ' has no hash', c.hash, undefined);
}
eq('truncated push description', cls('0021' + h32).description, 'Malformed script (a push runs past its end, so it can never be spent)');
eq('v0 21-byte description', cls('0015' + '5a'.repeat(21)).description, 'Invalid v0 witness program (21 bytes; v0 must be 20 or 32, so it can never be spent)');

process.exit(fails ? 1 : 0);
