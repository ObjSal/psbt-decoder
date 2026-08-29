// Security / sanity analysis of a normalized transaction model.
(function (root) {
  'use strict';
  const { Psbt } = root;

  const SAT = 100000000n;
  function btc(sats) {
    const neg = sats < 0n; const a = neg ? -sats : sats;
    const whole = a / SAT, frac = (a % SAT).toString().padStart(8, '0');
    return (neg ? '-' : '') + whole.toString() + '.' + frac + ' BTC';
  }
  function sats(n) { return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',') + ' sat'; }
  function fmtAmount(n) { return n === null || n === undefined ? 'unknown' : `${btc(n)} (${sats(n)})`; }

  const DUST = { p2wpkh: 294n, p2tr: 330n, p2wsh: 330n, p2pkh: 546n, p2sh: 540n, default: 546n };

  function analyze(model) {
    const checks = [];
    const add = (level, title, detail, extra) => checks.push({ level, title, detail, ...(extra || {}) });
    const { inputs, outputs, tx } = model;

    // --- Format
    if (model.kind === 'psbt') add('info', `PSBT version ${model.psbtVersion}`, `Partially Signed Bitcoin Transaction with ${inputs.length} input(s) and ${outputs.length} output(s).`);
    else add('info', 'Raw transaction (not a PSBT)', 'This is a serialized Bitcoin transaction. It carries no UTXO metadata, so input amounts and ownership cannot be verified from the data alone.');
    for (const w of model.warnings) add('warn', 'Parser warning', w);

    // --- Signing status
    const statusText = {
      unsigned: ['info', 'Unsigned', 'No signatures are present. Nothing can be broadcast from this data; it still needs to be signed by the required keys.'],
      partial: ['info', 'Partially signed', 'Some inputs are signed (or some multisig signatures are collected) but the transaction is not complete.'],
      signed: ['warn', 'Fully signed', 'All inputs carry the required signatures. Anyone holding this data can broadcast it — treat it as final.'],
      finalized: ['warn', 'Finalized', 'All inputs are finalized. The transaction can be extracted and broadcast by anyone holding this data.'],
      empty: ['danger', 'No inputs', 'Transaction has no inputs and is invalid.'],
    }[model.status];
    add(statusText[0], `Signing status: ${statusText[1]}`, statusText[2]);
    inputs.forEach(i => {
      if (i.status === 'partial') add('info', `Input #${i.index} partially signed`, `${i.have} of ${i.need} required signature(s) present (${i.spend.label}).`);
    });

    // --- Amounts and fee
    if (model.allInputsKnown) {
      if (model.fee < 0n) add('danger', 'Outputs exceed inputs', `Outputs total ${fmtAmount(model.totalOut)} but inputs total ${fmtAmount(model.totalIn)}. The transaction is invalid (creates money).`);
      else {
        const vsize = model.actualVsize || model.estimatedVsize;
        const rate = Number(model.fee) / vsize;
        const pct = model.totalIn > 0n ? Number(model.fee * 10000n / model.totalIn) / 100 : 0;
        const detail = `Fee ${fmtAmount(model.fee)} — ${pct.toFixed(2)}% of inputs; ≈${rate.toFixed(1)} sat/vB (${model.actualVsize ? 'actual' : 'estimated'} ${vsize} vB).`;
        if (model.fee === 0n) add('warn', 'Zero fee', detail + ' A zero-fee transaction will not relay on the network.');
        else if (pct > 20 || rate > 2000) add('danger', 'Absurdly high fee', detail + ' This looks like a fee-drain: verify the amounts before signing.');
        else if (pct > 5 || rate > 300) add('warn', 'Unusually high fee', detail);
        else if (rate < 1) add('warn', 'Fee below 1 sat/vB', detail + ' It may not relay or confirm.');
        else add('ok', 'Fee looks reasonable', detail);
      }
    } else if (inputs.length) {
      const missing = inputs.filter(i => i.value === null).map(i => '#' + i.index);
      add(model.kind === 'psbt' ? 'danger' : 'warn', 'Input amounts unknown — fee cannot be verified',
        `${missing.length === inputs.length ? 'No input' : 'Input(s) ' + missing.join(', ')} carr${missing.length === 1 ? 'ies' : 'y'} witness_utxo / non_witness_utxo data. Without it a signer cannot tell how much is being spent, so an attacker could hide a huge fee. ${model.kind === 'psbt' ? 'A well-formed PSBT for signing must include UTXO information.' : 'Use the "Input amounts" panel to paste the previous transactions or fetch them from an explorer.'}`);
    }
    if (model.externalUtxos) add('info', `${model.externalUtxos} input amount(s) supplied externally`, 'These amounts come from pasted previous transactions or a block explorer, not from the signed data. The fee shown is only as trustworthy as that source.');
    add('info', 'Totals', `Outputs: ${fmtAmount(model.totalOut)}${model.allInputsKnown ? ' · Inputs: ' + fmtAmount(model.totalIn) : ''}.`);

    // --- Per input checks
    const seen = new Set();
    for (const i of inputs) {
      const key = i.txid + ':' + i.vout;
      if (seen.has(key)) add('danger', `Duplicate input #${i.index}`, `Outpoint ${key} appears more than once. The transaction is invalid.`);
      seen.add(key);
      for (const p of i.problems) add(p.level, `Input #${i.index}`, p.text);
      // sighash
      const all = new Set([...i.sighashes, ...(i.declaredSighash !== undefined ? [i.declaredSighash] : [])]);
      for (const sh of all) {
        const name = Psbt.sighashName(sh);
        const base = sh & 0x1f, acp = sh & 0x80;
        if (base === 2) add('danger', `Input #${i.index} uses ${name}`, 'SIGHASH_NONE does not commit to any output: whoever holds this signature can redirect ALL the funds to themselves.');
        else if (base === 3) add('warn', `Input #${i.index} uses ${name}`, 'SIGHASH_SINGLE only commits to the output with the same index; other outputs can be changed after signing.');
        else if (acp) add('warn', `Input #${i.index} uses ${name}`, 'ANYONECANPAY lets other parties add inputs after you sign (normal for some coinjoin/crowdfund flows, otherwise suspicious).');
        else if (!(sh === 0 || sh === 1)) add('warn', `Input #${i.index} uses unknown sighash 0x${sh.toString(16)}`, 'Non-standard sighash flag.');
      }
      if (i.declaredSighash !== undefined && i.declaredSighash !== 1 && i.declaredSighash !== 0) { /* already reported above */ }
      if (i.spend.m === null && i.utxo) add('warn', `Input #${i.index}: script information missing`, `${i.spend.label}. The signer cannot know what conditions it is signing for.`);
      if (i.psbt && i.psbt.unknown && i.psbt.unknown.length) add('info', `Input #${i.index} has ${i.psbt.unknown.length} unknown field(s)`, i.psbt.unknown.map(u => `type 0x${u.type.toString(16)}`).join(', '));
      if (i.psbt && i.psbt.proprietary && i.psbt.proprietary.length) add('info', `Input #${i.index} has proprietary field(s)`, i.psbt.proprietary.map(p => p.identifierText || p.identifier).join(', '));
    }

    const wuOnly = inputs.filter(i => i.utxoSource === 'witness_utxo' && i.spend.segwit && !i.spend.taproot && model.kind === 'psbt');
    if (wuOnly.length) add('info', `${wuOnly.length === inputs.length ? 'All inputs carry' : wuOnly.length + ' input(s) carry'} witness_utxo only`, 'Fine for SegWit v0 (the amount is committed to by the signature), but some hardware wallets also require non_witness_utxo — the full previous transaction — to protect against fee-rate attacks.');

    // --- Outputs
    const addrCount = new Map();
    const inputAddrs = new Set(inputs.map(i => i.address).filter(Boolean));
    let external = 0n, change = 0n, opret = 0n, externalCount = 0, changeCount = 0;
    for (const o of outputs) {
      for (const p of o.problems) add(p.level, `Output #${o.index}`, p.text);
      const dust = DUST[o.type] || DUST.default;
      if (o.type === 'op_return') {
        opret += o.value;
        if (o.value > 0n) add('warn', `Output #${o.index} burns ${sats(o.value)}`, 'OP_RETURN outputs are unspendable; any value sent to them is destroyed.');
        else add('info', `Output #${o.index} is OP_RETURN data`, o.spkClass.dataText ? `"${o.spkClass.dataText}"` : `${(o.spkClass.data.length / 2)} bytes: ${o.spkClass.data.slice(0, 80)}${o.spkClass.data.length > 80 ? '…' : ''}`);
      } else if (o.value < dust) add('warn', `Output #${o.index} is dust (${sats(o.value)})`, 'Below the dust threshold; it will not relay on most nodes.');
      if (o.type === 'nonstandard' || o.type === 'witness_unknown' || o.type === 'empty') add('danger', `Output #${o.index} has a non-standard script`, `${o.spkClass.description}. Funds sent here may be unspendable.`);
      if (o.address) { addrCount.set(o.address, (addrCount.get(o.address) || 0) + 1); if (inputAddrs.has(o.address)) add('info', `Output #${o.index} pays back to an input address`, 'Self-transfer / address reuse detected.'); }
      if (o.isChange) { change += o.value; changeCount++; } else if (o.type !== 'op_return') { external += o.value; externalCount++; }
    }
    for (const [a, n] of addrCount) if (n > 1) add('info', 'Repeated destination', `${a} appears in ${n} outputs.`);
    if (model.kind === 'psbt' && model.fingerprints.length) {
      add(changeCount ? 'ok' : 'info', `${changeCount} change output(s) identified`, `${changeCount ? fmtAmount(change) + ' returns to a key with master fingerprint ' + model.fingerprints.join('/') + '. ' : ''}${externalCount} output(s) totalling ${fmtAmount(external)} go to external addresses with no derivation info — verify each one against the intended recipient.`);
    } else {
      add('warn', 'Change cannot be identified', model.kind === 'psbt' ? 'No BIP32 derivation paths are present, so none of the outputs can be proven to belong to the signer. Treat every output as an external payment and verify the addresses.' : 'A raw transaction carries no key information. Verify every destination address manually.');
    }
    if (outputs.length > 10) add('info', `${outputs.length} outputs`, 'Batch payment / distribution. Check that every destination is intended.');
    if (inputs.length > 10) add('info', `${inputs.length} inputs`, 'Many inputs are being consolidated into this transaction.');

    // --- Global
    if (tx.version < 1 || tx.version > 3) add('warn', `Unusual transaction version ${tx.version}`, 'Versions 1–3 are standard.');
    const rbf = inputs.some(i => i.sequence < 0xfffffffe);
    add('info', rbf ? 'Replace-by-fee signalled' : 'Not RBF-signalled', rbf ? 'At least one input has sequence < 0xfffffffe, so the transaction can be replaced by a higher-fee version before confirmation.' : 'All sequences are final; fee bumping would need CPFP.');
    if (tx.locktime) {
      const isHeight = tx.locktime < 500000000;
      const active = inputs.some(i => i.sequence !== 0xffffffff);
      add(active ? 'info' : 'warn', `Locktime ${isHeight ? 'height ' + tx.locktime : 'time ' + new Date(tx.locktime * 1000).toISOString()}`,
        active ? (isHeight ? 'The transaction is only valid once the chain reaches that block height (anti fee-sniping uses the current tip).' : 'The transaction is only valid after that timestamp.') : 'Locktime is set but every input uses sequence 0xffffffff, so it is NOT enforced.');
    }
    const g = model.psbt && model.psbt.global;
    if (g) {
      if (g.xpubs.length) add('info', `${g.xpubs.length} global xpub(s)`, g.xpubs.map(x => `${x.masterFingerprint} ${x.path} → ${x.encoded.slice(0, 12)}…`).join('; '));
      if (g.unknown.length) add('info', 'Unknown global fields', g.unknown.map(u => `type 0x${u.type.toString(16)}`).join(', '));
      if (g.proprietary.length) add('info', 'Proprietary global fields', g.proprietary.map(p => p.identifierText || p.identifier).join(', '));
    }

    // --- Verdict
    const levels = checks.map(c => c.level);
    let verdict, verdictTitle, verdictDetail;
    // Once every input is signed the next irreversible act is broadcasting, not signing.
    const act = (model.status === 'finalized' || model.status === 'signed' || model.status === 'signed?') ? 'broadcast' : 'sign';
    if (levels.includes('danger')) { verdict = 'danger'; verdictTitle = `Do not ${act} — critical issues found`; verdictDetail = 'One or more checks flagged a condition that can lose funds or indicates an invalid/malicious transaction.'; }
    else if (levels.includes('warn')) { verdict = 'caution'; verdictTitle = `Review carefully before ${act}ing`; verdictDetail = 'Structural checks passed, but there are warnings you should understand first.'; }
    else { verdict = 'ok'; verdictTitle = 'No structural problems found'; verdictDetail = 'Fee, sighash flags, scripts and UTXO data are consistent. Still confirm every external address and amount yourself — this tool cannot know who the recipients are.'; }
    const order = { danger: 0, warn: 1, ok: 2, info: 3 };
    checks.sort((a, b) => order[a.level] - order[b.level]);
    return { verdict, verdictTitle, verdictDetail, checks, external, change, opret, externalCount, changeCount };
  }

  root.Analysis = { analyze, btc, sats, fmtAmount };
})(typeof window !== 'undefined' ? window : globalThis);
