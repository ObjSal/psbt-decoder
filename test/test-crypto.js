const path = require('path');
const nodeCrypto = require('crypto');
require(path.join(__dirname, '../js/crypto.js'));
require(path.join(__dirname, '../js/bytes.js'));
require(path.join(__dirname, '../js/encoding.js'));
const { Crypto, Bytes, Encoding } = globalThis;
const enc = (s) => new TextEncoder().encode(s);
let fails = 0;
function eq(name, a, b) { if (a !== b) { fails++; console.log('FAIL', name, '\n got', a, '\n exp', b); } else console.log('ok  ', name); }

for (const msg of ['', 'abc', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'x'.repeat(1000)]) {
  eq('sha256 len ' + msg.length, Bytes.bytesToHex(Crypto.sha256(enc(msg))), nodeCrypto.createHash('sha256').update(msg).digest('hex'));
}
eq('ripemd160 ""', Bytes.bytesToHex(Crypto.ripemd160(enc(''))), '9c1185a5c5e9fc54612808977ee8f548b2258d31');
eq('ripemd160 abc', Bytes.bytesToHex(Crypto.ripemd160(enc('abc'))), '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc');
eq('ripemd160 alphabet', Bytes.bytesToHex(Crypto.ripemd160(enc('abcdefghijklmnopqrstuvwxyz'))), 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc');
eq('ripemd160 1M a', Bytes.bytesToHex(Crypto.ripemd160(enc('a'.repeat(1000000)))), '52783243c1697bdbe16d37f97f68f08325dc1528');

// P2PKH address from known pubkey hash (Satoshi's genesis coinbase pubkey → 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)
const gen = Bytes.hexToBytes('04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f');
const h160 = Crypto.hash160(gen);
eq('p2pkh genesis', Encoding.base58Check(Bytes.concat(Uint8Array.of(0), h160)), '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
// BIP173 vector: P2WPKH
eq('p2wpkh', Encoding.segwitAddress('bc', 0, Bytes.hexToBytes('751e76e8199196d454941c45d1b3a323f1433bd6')), 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
// BIP350 vector: P2TR
eq('p2tr', Encoding.segwitAddress('bc', 1, Bytes.hexToBytes('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')), 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0');
// BIP32 test vector 1 xpub
const xpub = Encoding.base58Decode('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8').slice(0, 78);
eq('xpub decode', Encoding.decodeXpub(xpub).encoded, 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8');
eq('xpub fingerprint', Encoding.decodeXpub(xpub).fingerprint, '3442193e');
process.exit(fails ? 1 : 0);
