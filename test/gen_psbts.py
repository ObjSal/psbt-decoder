"""Generate test PSBT fixtures with embit (independent implementation).

All mnemonics below are the well-known public BIP39 test vectors, and the
remaining keys are fixed dummy scalars - nothing here controls real funds.
"""
import json, hashlib
from embit import bip32, bip39, script, ec, psbt as P
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath

net = NETWORKS['main']
seed = bip39.mnemonic_to_seed('abandon '*11 + 'about')
root = bip32.HDKey.from_seed(seed)
fp = root.my_fingerprint
def key(path): return root.derive(path)
out = {}

def prev_tx(spk, amount):
    t = Transaction(vin=[TransactionInput(b'\x11'*32, 0)], vout=[TransactionOutput(amount, spk)])
    return t

# 1. P2WPKH single-sig: unsigned, signed, finalized
k0 = key("m/84h/0h/0h/0/0"); k1 = key("m/84h/0h/0h/1/0")
spk0 = script.p2wpkh(k0)
ptx = prev_tx(spk0, 150_000)
tx = Transaction(vin=[TransactionInput(ptx.txid(), 0, sequence=0xfffffffd)],
                 vout=[TransactionOutput(100_000, script.p2wpkh(ec.PrivateKey(b'\x01'*32).get_public_key())),
                       TransactionOutput(48_500, script.p2wpkh(k1))], locktime=850_000)
ps = PSBT(tx)
ps.inputs[0].witness_utxo = ptx.vout[0]
ps.inputs[0].bip32_derivations[k0.key] = DerivationPath(fp, bip32.parse_path("m/84h/0h/0h/0/0"))
ps.outputs[1].bip32_derivations[k1.key] = DerivationPath(fp, bip32.parse_path("m/84h/0h/0h/1/0"))
out['p2wpkh_unsigned'] = ps.to_string()
ps.sign_with(root)
out['p2wpkh_signed'] = ps.to_string()
# finalize
from embit import finalizer
ftx = finalizer.finalize_psbt(ps)
ps2 = PSBT(tx)
ps2.inputs[0].witness_utxo = ptx.vout[0]
ps2.outputs[1].bip32_derivations[k1.key] = DerivationPath(fp, bip32.parse_path("m/84h/0h/0h/1/0"))
for i, inp in enumerate(ps2.inputs):
    inp.final_scriptwitness = ftx.vin[i].witness
    inp.final_scriptsig = ftx.vin[i].script_sig
out['p2wpkh_finalized'] = ps2.to_string()
out['p2wpkh_final_tx'] = str(ftx)
out['p2wpkh_final_txid'] = ftx.txid().hex()

# 2. 2-of-3 P2WSH multisig, partially signed (1 of 2), with non_witness_utxo
seeds = [bip32.HDKey.from_seed(bip39.mnemonic_to_seed(m)) for m in ['abandon '*11+'about', 'zoo '*11+'wrong', 'legal winner thank year wave sausage worth useful legal winner thank yellow']]
ms_path = "m/48h/0h/0h/2h"
xpubs = [s.derive(ms_path) for s in seeds]
keys = [x.derive("0/0") for x in xpubs]
pubs = sorted([k.key for k in keys], key=lambda k: k.sec())
ws = script.multisig(2, pubs)
spk = script.p2wsh(ws)
ptx2 = prev_tx(spk, 1_000_000)
tx2 = Transaction(vin=[TransactionInput(ptx2.txid(), 0, sequence=0xffffffff)],
                  vout=[TransactionOutput(990_000, script.p2tr(ec.PrivateKey(b'\x02'*32).get_public_key()))])
ps3 = PSBT(tx2)
ps3.inputs[0].non_witness_utxo = ptx2
ps3.inputs[0].witness_utxo = ptx2.vout[0]
ps3.inputs[0].witness_script = ws
for s, x, k in zip(seeds, xpubs, keys):
    ps3.inputs[0].bip32_derivations[k.key] = DerivationPath(s.my_fingerprint, bip32.parse_path(ms_path + "/0/0"))
    ps3.xpubs[x.to_public()] = DerivationPath(s.my_fingerprint, bip32.parse_path(ms_path))
out['multisig_unsigned'] = ps3.to_string()
ps3.sign_with(seeds[0])
out['multisig_partial'] = ps3.to_string()

# 3. Taproot key-path, signed
kt = key("m/86h/0h/0h/0/0")
spk_t = script.p2tr(kt)
ptx3 = prev_tx(spk_t, 500_000)
tx3 = Transaction(vin=[TransactionInput(ptx3.txid(), 0, sequence=0xfffffffd)],
                  vout=[TransactionOutput(0, script.Script(b'\x6a\x0dhello taproot')), TransactionOutput(490_000, script.p2wpkh(k1))])
ps4 = PSBT(tx3)
ps4.inputs[0].witness_utxo = ptx3.vout[0]
ps4.inputs[0].taproot_bip32_derivations[kt.key] = ([], DerivationPath(fp, bip32.parse_path("m/86h/0h/0h/0/0")))
ps4.inputs[0].taproot_internal_key = kt.key
ps4.outputs[1].bip32_derivations[k1.key] = DerivationPath(fp, bip32.parse_path("m/84h/0h/0h/1/0"))
out['taproot_unsigned'] = ps4.to_string()
ps4.sign_with(root)
out['taproot_signed'] = ps4.to_string()

# 4. Malicious-looking: huge fee + SIGHASH_NONE declared, no change info
tx5 = Transaction(vin=[TransactionInput(ptx.txid(), 0)], vout=[TransactionOutput(10_000, script.p2wpkh(ec.PrivateKey(b'\x03'*32).get_public_key()))])
ps5 = PSBT(tx5)
ps5.inputs[0].witness_utxo = ptx.vout[0]
ps5.inputs[0].sighash_type = 2
out['trap_hugefee_sighashnone'] = ps5.to_string()

# 5. PSBT with no utxo info at all
ps6 = PSBT(tx)
out['no_utxo_info'] = ps6.to_string()

json.dump(out, open('test/fixtures.json', 'w'), indent=1)
print({k: len(v) for k, v in out.items()})
