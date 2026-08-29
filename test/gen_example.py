"""Generate the bundled demo data (test/example1.hex + test/example1.psbt.b64).

Everything here is synthetic: keys come from the public BIP39 test mnemonic
("abandon" x11 + "about") and the previous-output txids are just SHA256 of a label.
Nothing refers to a real on-chain transaction.
"""
import hashlib, json
from embit import bip32, bip39, script
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit.psbt import PSBT, DerivationPath

root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed('abandon ' * 11 + 'about'))
fp = root.my_fingerprint
# Arbitrary made-up amounts (sats); they do not correspond to any real transaction.
INPUT_AMOUNTS = [3_120_000, 750_000, 12_500_000, 208_311, 5_000_000, 1_999_000, 640_000]
PAYMENTS = [6_500_000, 2_000_000, 12_345_678, 420_000, 1_000_000]
FEE = 6_180
CHANGE = sum(INPUT_AMOUNTS) - sum(PAYMENTS) - FEE
assert CHANGE > 0

vin, ins_meta = [], []
for i, amount in enumerate(INPUT_AMOUNTS):
    k = root.derive(f"m/84h/0h/0h/0/{i}")
    txid = hashlib.sha256(f"psbt-decoder demo input {i}".encode()).digest()
    vin.append(TransactionInput(txid, i % 3, sequence=0xfffffffd))
    ins_meta.append((k, TransactionOutput(amount, script.p2wpkh(k))))

vout = []
change_key = root.derive("m/84h/0h/0h/1/3")
for j, amount in enumerate(PAYMENTS):
    # recipients: unrelated keys from a different account so they look external
    rk = root.derive(f"m/84h/0h/9h/0/{j}")
    vout.append(TransactionOutput(amount, script.p2wpkh(rk)))
    if j == 2:
        vout.append(TransactionOutput(CHANGE, script.p2wpkh(change_key)))
CHANGE_INDEX = 3

tx = Transaction(version=2, vin=vin, vout=vout, locktime=0)
open('test/example1.hex', 'w').write(tx.serialize().hex() + '\n')

ps = PSBT(tx)
for i, (k, utxo) in enumerate(ins_meta):
    ps.inputs[i].witness_utxo = utxo
    ps.inputs[i].bip32_derivations[k.key] = DerivationPath(fp, bip32.parse_path(f"m/84h/0h/0h/0/{i}"))
ps.outputs[CHANGE_INDEX].bip32_derivations[change_key.key] = DerivationPath(fp, bip32.parse_path("m/84h/0h/0h/1/3"))
open('test/example1.psbt.b64', 'w').write(ps.to_string() + '\n')
print('inputs', len(vin), 'outputs', len(vout), 'change', CHANGE, 'tx bytes', len(tx.serialize()), 'psbt chars', len(ps.to_string()), 'txid', tx.txid().hex())
