// Rendering: verdict banner, stats, Sankey-style flow diagram, checks, cards, annotated hex, JSON.
(function (root) {
  'use strict';
  const { Bytes, Script, Psbt, Analysis } = root;
  const { btc, sats } = Analysis;

  const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const short = (s, a = 10, b = 8) => (s && s.length > a + b + 3) ? s.slice(0, a) + '…' + s.slice(-b) : (s || '');
  const hex = Bytes.bytesToHex;
  const fmtBtc = (n) => n === null || n === undefined ? '?' : btc(n);
  const explorerBase = (network) => ({ mainnet: 'https://mempool.space', testnet: 'https://mempool.space/testnet', signet: 'https://mempool.space/signet', regtest: null }[network]);
  const txLink = (network, txid) => { const b = explorerBase(network); return b ? `<a href="${b}/tx/${txid}" target="_blank" rel="noopener">${txid}</a>` : txid; };
  const addrLink = (network, addr) => { const b = explorerBase(network); return b ? `<a href="${b}/address/${addr}" target="_blank" rel="noopener">${esc(addr)}</a>` : esc(addr); };
  const copyBtn = (text) => `<span class="copy" data-copy="${esc(text)}" title="Copy">copy</span>`;

  const ICONS = {
    ok: '<svg viewBox="0 0 16 16" fill="#3fb950"><path d="M8 16A8 8 0 118 0a8 8 0 010 16zm3.78-9.72a.75.75 0 00-1.06-1.06L6.75 9.19 5.28 7.72a.75.75 0 00-1.06 1.06l2 2a.75.75 0 001.06 0l4.5-4.5z"/></svg>',
    warn: '<svg viewBox="0 0 16 16" fill="#d29922"><path d="M6.457 1.047c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575L6.457 1.047zM8 5a.75.75 0 00-.75.75v2.5a.75.75 0 001.5 0v-2.5A.75.75 0 008 5zm1 6a1 1 0 10-2 0 1 1 0 002 0z"/></svg>',
    danger: '<svg viewBox="0 0 16 16" fill="#f85149"><path d="M8 16A8 8 0 118 0a8 8 0 010 16zM5.28 4.22a.75.75 0 00-1.06 1.06L6.94 8l-2.72 2.72a.75.75 0 101.06 1.06L8 9.06l2.72 2.72a.75.75 0 101.06-1.06L9.06 8l2.72-2.72a.75.75 0 00-1.06-1.06L8 6.94 5.28 4.22z"/></svg>',
    info: '<svg viewBox="0 0 16 16" fill="#58a6ff"><path d="M8 16A8 8 0 118 0a8 8 0 010 16zm.75-11a.75.75 0 10-1.5 0 .75.75 0 001.5 0zM7 7.25a.75.75 0 011.5 0v3.5a.75.75 0 01-1.5 0v-3.5z"/></svg>',
  };
  const STATUS_CHIP = { unsigned: ['gray', 'Unsigned'], partial: ['yellow', 'Partially signed'], signed: ['green', 'Fully signed'], finalized: ['green', 'Finalized'], empty: ['red', 'No inputs'], 'signed?': ['green', 'Signed'] };

  // ------------------------------------------------------------------ verdict + stats
  function renderVerdict(el, model, a) {
    const cls = a.verdict === 'ok' ? 'ok' : a.verdict;
    const icon = a.verdict === 'ok' ? ICONS.ok : a.verdict === 'caution' ? ICONS.warn : ICONS.danger;
    const st = STATUS_CHIP[model.status];
    el.innerHTML = `<div class="verdict ${cls}"><div class="icon">${icon}</div><div><div class="title">${esc(a.verdictTitle)}</div><div class="detail">${esc(a.verdictDetail)}</div></div>
      <div class="chips"><span class="chip purple">${model.kind === 'psbt' ? 'PSBT v' + model.psbtVersion : 'Raw transaction'}</span><span class="chip ${st[0]}">${st[1]}</span><span class="chip gray">${Script.NETWORKS[model.network].name}</span></div></div>`;
  }

  function renderStats(el, model, a) {
    const tiles = [];
    const t = (k, v, s, opts = {}) => tiles.push(`<div class="stat${opts.wide ? ' wide' : ''}"><div class="k">${esc(k)}</div><div class="v${opts.mono ? ' mono' : ''}${opts.cls ? ' ' + opts.cls : ''}" title="${esc(v)}">${opts.html ? v : esc(v)}</div>${s ? `<div class="s" title="${esc(s)}">${esc(s)}</div>` : ''}</div>`);
    const tx = model.tx;
    t('Inputs', String(model.inputs.length), model.allInputsKnown ? 'all amounts known' : `${model.inputs.filter(i => i.value !== null).length} with known amount`);
    t('Outputs', String(model.outputs.length), `${a.externalCount} external · ${a.changeCount} change${model.outputs.some(o => o.type === 'op_return') ? ' · OP_RETURN' : ''}`);
    t('Total in', model.totalIn === null ? 'unknown' : btc(model.totalIn), model.totalIn === null ? 'no UTXO data' : sats(model.totalIn), { cls: model.totalIn === null ? 'warn' : '' });
    t('Total out', btc(model.totalOut), sats(model.totalOut));
    const feeCheck = a.checks.find(c => /fee/i.test(c.title) && c.level !== 'info');
    const feeCls = feeCheck ? (feeCheck.level === 'ok' ? 'ok' : feeCheck.level) : '';
    t('Fee', model.fee === null ? 'unknown' : btc(model.fee), model.fee === null ? 'cannot verify' : sats(model.fee) + (model.totalIn > 0n ? ` · ${(Number(model.fee * 10000n / model.totalIn) / 100).toFixed(2)}% of inputs` : ''), { cls: feeCls });
    const vs = model.actualVsize || model.estimatedVsize;
    t('Fee rate', model.fee === null ? '—' : (Number(model.fee) / vs).toFixed(1) + ' sat/vB', model.actualVsize ? `actual ${vs} vB` : `estimated ${vs} vB when signed`, { cls: feeCls });
    t('Size', `${tx.size} B`, `${tx.vsize} vB · ${tx.weight} WU${model.kind === 'psbt' ? ' (unsigned tx) · PSBT ' + model.bytes.length + ' B' : ''}`);
    const rbf = model.inputs.some(i => i.sequence < 0xfffffffe);
    t('Version / locktime', `v${tx.version} · ${tx.locktime === 0 ? 'no locktime' : tx.locktime}`, rbf ? 'RBF signalled' : 'not replaceable (no RBF)');
    const txidLabel = model.finalTx ? 'txid' : 'txid (unsigned)';
    const txid = model.finalTx ? model.finalTx.txid : tx.txid;
    t(txidLabel, txLink(model.network, txid) + copyBtn(txid), model.finalTx && model.finalTx.hasWitness ? 'wtxid ' + model.finalTx.wtxid : (model.kind === 'psbt' && model.inputs.some(i => !i.spend.segwit && i.spkClass) ? 'legacy inputs: txid changes once signed' : ''), { wide: true, mono: true, html: true });
    el.innerHTML = tiles.join('');
  }

  // ------------------------------------------------------------------ flow diagram
  const COLORS = { input: '#39c5cf', unsignedInput: '#4a7b80', external: '#3fb950', change: '#58a6ff', op_return: '#bc8cff', fee: '#f0883e', unknown: '#6e7681', danger: '#f85149' };

  function renderFlow(el, model, a) {
    const ins = model.inputs, outs = model.outputs;
    const feeRow = model.fee !== null && model.fee > 0n;
    const nL = ins.length, nR = outs.length + (feeRow ? 1 : 0);
    const many = Math.max(nL, nR) > 60;
    const rowH = many ? 16 : 30, gap = many ? 3 : 8, padTop = 34, padBot = 12;
    const W = 1000, labelW = 300, barW = 12, cxW = 22;
    const H = Math.max(nL, nR) * rowH + padTop + padBot;
    const xInBar = labelW, xOutBar = W - labelW - barW, cx = W / 2 - cxW / 2;

    // Values → thickness
    const outVals = outs.map(o => o.value);
    if (feeRow) outVals.push(model.fee);
    const sumOut = outVals.reduce((s, v) => s + v, 0n);
    const knownIn = model.allInputsKnown;
    const inVals = knownIn ? ins.map(i => i.value) : ins.map(() => sumOut / BigInt(Math.max(1, nL)) || 1n);
    const sumIn = inVals.reduce((s, v) => s + v, 0n);
    const maxRow = rowH - gap;
    const maxVal = Number([...inVals, ...outVals].reduce((m, v) => v > m ? v : m, 0n)) || 1;
    const total = Number(sumIn > sumOut ? sumIn : sumOut) || 1;
    const k = Math.min(maxRow / maxVal, (H - padTop - padBot) / total);
    const th = (v) => Math.max(1.5, Number(v) * k);

    const inTh = inVals.map(th), outTh = outVals.map(th);
    const centerH = Math.max(inTh.reduce((s, v) => s + v, 0), outTh.reduce((s, v) => s + v, 0));
    const cyTop = padTop + ((H - padTop - padBot) - centerH) / 2;

    const parts = [];
    parts.push(`<text class="head" x="${xInBar + barW}" y="18" text-anchor="end">${nL} input${nL === 1 ? '' : 's'}${knownIn ? ' · ' + esc(btc(sumIn)) : ' · amounts unknown'}</text>`);
    parts.push(`<text class="head" x="${xOutBar}" y="18">${outs.length} output${outs.length === 1 ? '' : 's'} · ${esc(btc(model.totalOut))}${feeRow ? ' + fee' : ''}</text>`);
    parts.push(`<rect class="center" x="${cx}" y="${cyTop}" width="${cxW}" height="${Math.max(centerH, 2)}" rx="3"/>`);
    parts.push(`<text class="head" x="${W / 2}" y="${cyTop - 6}" text-anchor="middle">tx</text>`);

    const ribbon = (x0, y0, t0, x1, y1, t1, color, title, dashed) => {
      const c = (x0 + x1) / 2;
      const d = `M${x0},${y0} C${c},${y0} ${c},${y1} ${x1},${y1} L${x1},${y1 + t1} C${c},${y1 + t1} ${c},${y0 + t0} ${x0},${y0 + t0} Z`;
      return `<path class="ribbon" d="${d}" fill="${color}"${dashed ? ' stroke="' + color + '" stroke-dasharray="4 3" fill-opacity=".35"' : ''}><title>${esc(title)}</title></path>`;
    };
    // Inputs
    let cyIn = cyTop;
    ins.forEach((inp, i) => {
      const t = inTh[i];
      const y = padTop + i * rowH + rowH / 2;
      const signed = inp.status === 'signed' || inp.status === 'finalized';
      const color = inp.problems.some(p => p.level === 'danger') ? COLORS.danger : signed ? COLORS.input : (inp.status === 'partial' ? '#8fd3d8' : COLORS.unsignedInput);
      const label = `#${i} · ${inp.value === null ? 'amount unknown' : btc(inp.value)} · ${inp.spend.label} · ${STATUS_CHIP[inp.status] ? STATUS_CHIP[inp.status][1] : inp.status}`;
      parts.push(`<rect class="bar" x="${xInBar}" y="${y - t / 2}" width="${barW}" height="${t}" fill="${color}"><title>${esc(label)}</title></rect>`);
      parts.push(ribbon(xInBar + barW, y - t / 2, t, cx, cyIn, t, color, label, !knownIn));
      cyIn += t;
      const l1 = `#${i}  ${inp.value === null ? '? BTC' : btc(inp.value)}`;
      const l2 = inp.address ? short(inp.address, 12, 8) : short(inp.txid, 8, 6) + ':' + inp.vout;
      if (many) parts.push(`<text x="${xInBar - 8}" y="${y + 4}" text-anchor="end">${esc(l1)} <tspan class="sub">${esc(l2)}</tspan></text>`);
      else parts.push(`<text x="${xInBar - 8}" y="${y - 1}" text-anchor="end">${esc(l1)}</text><text class="sub" x="${xInBar - 8}" y="${y + 11}" text-anchor="end">${esc(l2)} · ${esc(STATUS_CHIP[inp.status] ? STATUS_CHIP[inp.status][1] : inp.status)}</text>`);
    });
    // Outputs
    let cyOut = cyTop;
    const outRows = outs.map((o, i) => ({ kind: o.isChange ? 'change' : (o.type === 'op_return' ? 'op_return' : (o.problems.some(p => p.level === 'danger') || ['nonstandard', 'witness_unknown', 'empty'].includes(o.type) ? 'danger' : 'external')), value: o.value, idx: i, label: `#${i} · ${btc(o.value)} · ${o.isChange ? 'change (yours)' : o.type === 'op_return' ? 'OP_RETURN' : 'external'} · ${o.address || o.spkClass.description}`, sub: o.address ? short(o.address, 12, 8) : o.spkClass.description }));
    if (feeRow) outRows.push({ kind: 'fee', value: model.fee, idx: null, label: `Miner fee · ${btc(model.fee)}`, sub: 'miner fee' });
    outRows.forEach((o, i) => {
      const t = outTh[i];
      const y = padTop + i * rowH + rowH / 2;
      const color = COLORS[o.kind];
      parts.push(`<rect class="bar" x="${xOutBar}" y="${y - t / 2}" width="${barW}" height="${t}" fill="${color}"><title>${esc(o.label)}</title></rect>`);
      parts.push(ribbon(cx + cxW, cyOut, t, xOutBar, y - t / 2, t, color, o.label, false));
      cyOut += t;
      const l1 = `${o.idx === null ? 'fee' : '#' + o.idx}  ${btc(o.value)}`;
      const tag = o.kind === 'change' ? 'change' : o.kind === 'fee' ? '' : o.kind === 'op_return' ? 'data' : o.kind === 'danger' ? 'NON-STANDARD' : 'external';
      if (many) parts.push(`<text x="${xOutBar + barW + 8}" y="${y + 4}">${esc(l1)} <tspan class="sub">${esc(o.sub)}</tspan></text>`);
      else parts.push(`<text x="${xOutBar + barW + 8}" y="${y - 1}">${esc(l1)}${tag ? ` <tspan fill="${color}" font-size="10">${tag}</tspan>` : ''}</text><text class="sub" x="${xOutBar + barW + 8}" y="${y + 11}">${esc(o.sub)}</text>`);
    });
    el.innerHTML = `<svg class="flow" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMin meet" style="min-width:${Math.min(W, 760)}px">${parts.join('')}</svg>
      <div class="legend"><span style="--c:${COLORS.input}">signed input</span><span style="--c:${COLORS.unsignedInput}">unsigned input</span><span style="--c:${COLORS.external}">external output</span><span style="--c:${COLORS.change}">change (back to signer)</span><span style="--c:${COLORS.fee}">miner fee</span><span style="--c:${COLORS.op_return}">OP_RETURN</span><span style="--c:${COLORS.danger}">problem</span></div>`;
  }

  function renderMoneyBar(el, model, a) {
    const totalOut = model.totalOut + (model.fee && model.fee > 0n ? model.fee : 0n);
    if (totalOut <= 0n) { el.innerHTML = ''; return; }
    const seg = (v, color, label) => v > 0n ? `<div style="width:${Number(v * 10000n / totalOut) / 100}%;background:${color}" data-label="${esc(label)}: ${esc(btc(v))} (${(Number(v * 10000n / totalOut) / 100).toFixed(2)}%)"></div>` : '';
    el.innerHTML = `<div class="moneybar">${seg(a.external, COLORS.external, 'External')}${seg(a.change, COLORS.change, 'Change')}${seg(model.fee && model.fee > 0n ? model.fee : 0n, COLORS.fee, 'Fee')}${seg(a.opret, COLORS.op_return, 'Burned in OP_RETURN')}</div>
      <div class="legend"><span style="--c:${COLORS.external}">${esc(btc(a.external))} to ${a.externalCount} external address${a.externalCount === 1 ? '' : 'es'}</span><span style="--c:${COLORS.change}">${esc(btc(a.change))} change</span><span style="--c:${COLORS.fee}">${model.fee === null ? 'fee unknown' : esc(btc(model.fee)) + ' fee'}</span></div>`;
  }

  // ------------------------------------------------------------------ checks
  function renderChecks(el, a) {
    const counts = { danger: 0, warn: 0, ok: 0, info: 0 };
    a.checks.forEach(c => counts[c.level]++);
    el.innerHTML = `<div class="checks-filter">${['danger', 'warn', 'ok', 'info'].map(l => `<span class="chip ${{ danger: 'red', warn: 'yellow', ok: 'green', info: 'blue' }[l]}">${counts[l]} ${l === 'warn' ? 'warning' : l}${counts[l] === 1 || l === 'info' ? '' : 's'}</span>`).join('')}</div>
      <div class="checks">${a.checks.map(c => `<div class="check ${c.level}"><div class="ic">${ICONS[c.level]}</div><div><div class="t">${esc(c.title)}</div><div class="d">${esc(c.detail)}</div></div></div>`).join('')}</div>`;
  }

  // ------------------------------------------------------------------ scripts
  function classifyPush(d) {
    if (Script.isPubkey(d)) return ['pubkey', 'pubkey'];
    if (Script.isDERSig(d)) return ['sig', 'sig'];
    if (d.length === 20) return ['hash', 'hash160'];
    if (d.length === 32) return ['hash', '32B'];
    if (d.length === 64 || d.length === 65) return ['sig', 'sig?'];
    if (d.length <= 4) return ['num', 'num'];
    return ['data', 'data'];
  }
  function opClass(t) {
    if (t.disabled) return 'opcode disabled';
    if (/CHECKSIG|CHECKMULTISIG|SHA|HASH|RIPEMD|CHECKSIGADD/.test(t.name)) return 'opcode crypto';
    if (/OP_(IF|NOTIF|ELSE|ENDIF|VERIFY|RETURN|CHECKLOCKTIMEVERIFY|CHECKSEQUENCEVERIFY)$/.test(t.name)) return 'opcode flow';
    return 'opcode';
  }
  function scriptOps(bytes) {
    if (!bytes.length) return '<span class="muted">(empty)</span>';
    return Script.disassemble(bytes).map(t => {
      if (t.error) return `<span class="op err" title="${esc(t.error)}">${esc(t.name)} ${hex(t.data)} ✖ ${esc(t.error)}</span>`;
      if (t.data) {
        if (!t.data.length) return `<span class="op num">OP_0</span>`;
        const [cls, lbl] = classifyPush(t.data);
        let extra = '';
        if (cls === 'sig' && Script.isDERSig(t.data)) extra = ` <span class="lbl">${esc(Psbt.sighashName(t.data[t.data.length - 1]))}</span>`;
        if (cls === 'num') { let n = 0; for (let i = t.data.length - 1; i >= 0; i--) n = n * 256 + t.data[i]; if (t.data[t.data.length - 1] & 0x80) n = -(n - (0x80 << (8 * (t.data.length - 1)))); extra = ` <span class="lbl">= ${n}</span>`; }
        return `<span class="op data ${cls}" title="${t.data.length} bytes: ${hex(t.data)}"><span class="lbl">${lbl}</span>${hex(t.data)}${extra}</span>`;
      }
      if (t.num !== undefined) return `<span class="op num">${esc(t.name)}</span>`;
      return `<span class="op ${opClass(t)}">${esc(t.name)}</span>`;
    }).join('');
  }
  function scriptBlock(title, bytes, opts = {}) {
    const info = opts.info || null;
    return `<div class="scriptblock"><div class="sh"><b>${esc(title)}</b>${info ? `<span class="chip gray">${esc(Script.TYPE_LABELS[info.type] || info.type)}</span><span class="desc">${esc(info.description || '')}</span>` : ''}${info && info.features && info.features.length ? info.features.map(f => `<span class="chip ${/DISABLED|MALFORMED/.test(f) ? 'red' : 'yellow'}">${esc(f)}</span>`).join('') : ''}<span class="muted" style="margin-left:auto">${bytes.length} B</span><button class="small togglehex">hex</button></div><div class="ops">${scriptOps(bytes)}</div><div class="hexline">${hex(bytes) || '(empty)'}${copyBtn(hex(bytes))}</div></div>`;
  }
  function witnessBlock(title, items) {
    return `<div class="scriptblock"><div class="sh"><b>${esc(title)}</b><span class="desc">${items.length} item${items.length === 1 ? '' : 's'}</span></div><div class="wstack">${items.length ? items.map((w, i) => { const [cls, lbl] = w.length ? classifyPush(w) : ['num', 'empty']; const sh = Script.isDERSig(w) ? ' ' + Psbt.sighashName(w[w.length - 1]) : (w.length === 65 && !Script.isPubkey(w) ? ' ' + Psbt.sighashName(w[64]) : ''); return `<div><span class="i">[${i}]</span><span class="op data ${cls}" style="white-space:normal"><span class="lbl">${lbl}${esc(sh)}</span>${w.length ? hex(w) : '(empty)'}</span></div>`; }).join('') : '<span class="muted">(empty)</span>'}</div></div>`;
  }

  function seqDescription(seq) {
    if (seq === 0xffffffff) return 'final (no RBF, locktime disabled)';
    if (seq === 0xfffffffe) return 'locktime enabled, no RBF';
    let s = 'RBF signalled';
    if (!(seq & 0x80000000)) { const v = seq & 0xffff; s += (seq & 0x400000) ? ` · relative timelock ${v * 512}s (${v} × 512s)` : ` · relative timelock ${v} block${v === 1 ? '' : 's'}`; }
    return s;
  }

  // ------------------------------------------------------------------ inputs / outputs
  function renderInputs(el, model) {
    el.innerHTML = model.inputs.map(inp => {
      const p = inp.psbt || {};
      const st = STATUS_CHIP[inp.status] || ['gray', inp.status];
      const kv = [];
      const row = (k, v, sans) => kv.push(`<div class="k">${esc(k)}</div><div class="v${sans ? ' sans' : ''}">${v}</div>`);
      inp.problems.forEach(pr => row('⚠ Problem', `<span class="problem ${pr.level}">${esc(pr.text)}</span>`, true));
      row('Outpoint', `${txLink(model.network, inp.txid)}:${inp.vout}${copyBtn(inp.txid + ':' + inp.vout)}`);
      row('Amount', inp.value === null ? '<span class="problem warn">unknown (no UTXO data)</span>' : `${esc(btc(inp.value))} · ${esc(sats(inp.value))}`, true);
      if (inp.address) row('Address', `${addrLink(model.network, inp.address)}${copyBtn(inp.address)}`);
      row('Spend type', `${esc(inp.spend.label)}${inp.spend.inferred ? ' <span class="muted">(inferred)</span>' : ''}`, true);
      if (inp.utxoSource) row('UTXO source', esc(inp.utxoSource) + (inp.psbt && inp.psbt.nonWitnessUtxo ? ` · previous tx ${inp.psbt.nonWitnessUtxo.size} B, ${inp.psbt.nonWitnessUtxo.outputs.length} outputs` : ''), true);
      row('Sequence', `0x${inp.sequence.toString(16).padStart(8, '0')} <span class="muted">${esc(seqDescription(inp.sequence))}</span>`);
      const sigLines = [];
      for (const s of inp.signatures) sigLines.push(`<div><span class="chip green">${s.kind}</span> ${s.pubkey ? short(s.pubkey, 12, 8) : '(key path)'} · ${esc(Psbt.sighashName(s.sighash))}${s.leafHash ? ' · leaf ' + short(s.leafHash, 8, 6) : ''}</div>`);
      if (!inp.signatures.length && inp.rawSignatures.length) for (const s of inp.rawSignatures) sigLines.push(`<div><span class="chip green">${s.kind}</span> ${short(s.sig, 12, 8)} · ${esc(Psbt.sighashName(s.sighash))}</div>`);
      row('Signatures', `${inp.need === null ? `${inp.signatures.length} present (requirement unknown)` : `${inp.have} of ${inp.need} required`}${sigLines.length ? sigLines.join('') : ' <span class="muted">— none</span>'}`, true);
      if (inp.declaredSighash !== undefined) row('Declared sighash', esc(Psbt.sighashName(inp.declaredSighash)) + ` (0x${inp.declaredSighash.toString(16).padStart(2, '0')})`, true);
      if (p.bip32 && p.bip32.length) row('BIP32 derivation', p.bip32.map(d => `<div>[${d.fingerprint}] ${esc(d.pathStr)} → ${short(d.pubkey, 14, 8)}</div>`).join(''));
      if (p.tapBip32 && p.tapBip32.length) row('Taproot derivation', p.tapBip32.map(d => `<div>[${d.fingerprint}] ${esc(d.pathStr)} → ${short(d.xonly, 14, 8)}${d.leafHashes.length ? ` (${d.leafHashes.length} leaf hash${d.leafHashes.length === 1 ? '' : 'es'})` : ''}</div>`).join(''));
      if (p.tapInternalKey) row('Taproot internal key', p.tapInternalKey);
      if (p.tapMerkleRoot) row('Taproot merkle root', p.tapMerkleRoot);
      if (p.requiredTimeLocktime !== undefined) row('Required time locktime', String(p.requiredTimeLocktime));
      if (p.requiredHeightLocktime !== undefined) row('Required height locktime', String(p.requiredHeightLocktime));
      if (p.preimages && p.preimages.length) row('Hash preimages', p.preimages.map(h => `<div>${h.algo}(${short(h.preimage, 10, 6)}) = ${short(h.hash, 10, 6)}</div>`).join(''));
      if (p.porCommitment) row('PoR commitment', esc(p.porCommitment), true);
      if (p.proprietary && p.proprietary.length) row('Proprietary', p.proprietary.map(x => `<div>${esc(x.identifierText || x.identifier)} sub=${x.subtype} key=${short(x.keyData, 12, 6)} value=${short(x.value, 16, 8)}</div>`).join(''));
      if (p.unknown && p.unknown.length) row('Unknown fields', p.unknown.map(u => `<div>type 0x${u.type.toString(16)} key=${short(u.key, 12, 6)} value=${short(u.value, 16, 8)}</div>`).join(''));

      const scripts = [];
      if (inp.utxo) scripts.push(scriptBlock('scriptPubKey (previous output)', inp.utxo.script, { info: inp.spkClass }));
      if (inp.redeemScript) scripts.push(scriptBlock('redeemScript', inp.redeemScript, { info: Script.classifyInner(inp.redeemScript, model.network) }));
      if (inp.witnessScript) scripts.push(scriptBlock('witnessScript', inp.witnessScript, { info: Script.classifyInner(inp.witnessScript, model.network) }));
      if (p.tapLeafScripts) p.tapLeafScripts.forEach((l, i) => scripts.push(scriptBlock(`Tap leaf script #${i} (v0x${l.leafVersion.toString(16)})`, l.script, { info: Script.classifyInner(l.script, model.network) })));
      if (inp.scriptSig && (inp.scriptSig.length || model.kind === 'psbt')) scripts.push(scriptBlock(model.kind === 'psbt' ? 'final scriptSig' : 'scriptSig', inp.scriptSig));
      if (inp.witness && (inp.witness.length || model.kind === 'psbt')) scripts.push(witnessBlock(model.kind === 'psbt' ? 'final scriptWitness' : 'witness', inp.witness));

      return `<div class="card" data-idx="${inp.index}"><div class="head"><span class="idx">#${inp.index}</span><span class="chip ${st[0]}">${st[1]}</span><span class="chip gray">${esc(Script.TYPE_LABELS[inp.spend.type] || inp.spend.type)}</span><span class="addr">${esc(inp.address || (short(inp.txid, 12, 8) + ':' + inp.vout))}</span>${inp.problems.length ? `<span class="chip red">${inp.problems.length} problem${inp.problems.length === 1 ? '' : 's'}</span>` : ''}<span class="amt">${inp.value === null ? '?' : esc(btc(inp.value))}</span><span class="caret">▶</span></div>
        <div class="body"><div class="kv">${kv.join('')}</div>${scripts.join('')}</div></div>`;
    }).join('');
  }

  function renderOutputs(el, model) {
    el.innerHTML = model.outputs.map(o => {
      const kv = [];
      const row = (k, v, sans) => kv.push(`<div class="k">${esc(k)}</div><div class="v${sans ? ' sans' : ''}">${v}</div>`);
      o.problems.forEach(pr => row('⚠ Problem', `<span class="problem ${pr.level}">${esc(pr.text)}</span>`, true));
      row('Amount', `${esc(btc(o.value))} · ${esc(sats(o.value))}`, true);
      if (o.address) row('Address', `${addrLink(model.network, o.address)}${copyBtn(o.address)}`);
      row('Script type', `${esc(o.spkClass.description)}`, true);
      if (o.type === 'op_return') row('Data', `${o.spkClass.dataText ? '<div>"' + esc(o.spkClass.dataText) + '"</div>' : ''}<div class="muted">${o.spkClass.data || '(none)'}</div>`);
      row('Ownership', o.isChange ? `<span class="chip blue">change</span> derivation path matches an input key (fingerprint ${o.bip32.map(d => d.fingerprint).join(', ')})` : o.hasDerivation ? `<span class="chip yellow">derivation present</span> but master fingerprint ${o.bip32.map(d => d.fingerprint).join(', ')} does not match any input` : o.type === 'op_return' ? '<span class="chip purple">data</span>' : '<span class="chip green">external</span> no derivation info — verify this address', true);
      if (o.bip32.length) row('BIP32 derivation', o.bip32.map(d => `<div>[${d.fingerprint}] ${esc(d.pathStr)} → ${short(d.pubkey || d.xonly, 14, 8)}</div>`).join(''));
      const p = o.psbt || {};
      if (p.tapInternalKey) row('Taproot internal key', p.tapInternalKey);
      if (p.tapTree) row('Taproot tree', short(p.tapTree, 40, 20));
      if (p.proprietary && p.proprietary.length) row('Proprietary', p.proprietary.map(x => `<div>${esc(x.identifierText || x.identifier)} sub=${x.subtype} value=${short(x.value, 16, 8)}</div>`).join(''));
      if (p.unknown && p.unknown.length) row('Unknown fields', p.unknown.map(u => `<div>type 0x${u.type.toString(16)} value=${short(u.value, 16, 8)}</div>`).join(''));
      const scripts = [scriptBlock('scriptPubKey', o.script, { info: o.spkClass })];
      if (o.redeemScript) scripts.push(scriptBlock('redeemScript', o.redeemScript, { info: Script.classifyInner(o.redeemScript, model.network) }));
      if (o.witnessScript) scripts.push(scriptBlock('witnessScript', o.witnessScript, { info: Script.classifyInner(o.witnessScript, model.network) }));
      const chip = o.isChange ? '<span class="chip blue">change</span>' : o.type === 'op_return' ? '<span class="chip purple">OP_RETURN</span>' : ['nonstandard', 'witness_unknown', 'empty'].includes(o.type) ? '<span class="chip red">non-standard</span>' : '<span class="chip green">external</span>';
      return `<div class="card" data-idx="${o.index}"><div class="head"><span class="idx">#${o.index}</span>${chip}<span class="chip gray">${esc(Script.TYPE_LABELS[o.type] || o.type)}</span><span class="addr">${esc(o.address || o.spkClass.description)}</span>${o.problems.length ? `<span class="chip red">${o.problems.length} problem${o.problems.length === 1 ? '' : 's'}</span>` : ''}<span class="amt">${esc(btc(o.value))}</span><span class="caret">▶</span></div>
        <div class="body"><div class="kv">${kv.join('')}</div>${scripts.join('')}</div></div>`;
    }).join('');
  }

  function renderScripts(el, model) {
    const uniq = new Map();
    const addS = (bytes, role, info) => { if (!bytes) return; const k = hex(bytes); if (!uniq.has(k)) uniq.set(k, { bytes, roles: [], info }); uniq.get(k).roles.push(role); };
    model.inputs.forEach(i => {
      if (i.utxo) addS(i.utxo.script, `input #${i.index} prevout`, i.spkClass);
      addS(i.redeemScript, `input #${i.index} redeemScript`, i.redeemScript && Script.classifyInner(i.redeemScript, model.network));
      addS(i.witnessScript, `input #${i.index} witnessScript`, i.witnessScript && Script.classifyInner(i.witnessScript, model.network));
      (i.psbt && i.psbt.tapLeafScripts || []).forEach((l, k) => addS(l.script, `input #${i.index} tapleaf #${k}`, Script.classifyInner(l.script, model.network)));
    });
    model.outputs.forEach(o => {
      addS(o.script, `output #${o.index}`, o.spkClass);
      addS(o.redeemScript, `output #${o.index} redeemScript`, o.redeemScript && Script.classifyInner(o.redeemScript, model.network));
      addS(o.witnessScript, `output #${o.index} witnessScript`, o.witnessScript && Script.classifyInner(o.witnessScript, model.network));
    });
    // Type summary
    const typeCounts = {};
    model.outputs.forEach(o => { typeCounts[o.type] = (typeCounts[o.type] || 0) + 1; });
    const summary = `<div class="legend" style="margin:0 0 12px">${Object.entries(typeCounts).map(([t, n]) => `<span class="chip gray">${n} × ${esc(Script.TYPE_LABELS[t] || t)} output${n === 1 ? '' : 's'}</span>`).join('')}<span class="chip gray">${uniq.size} unique script${uniq.size === 1 ? '' : 's'}</span></div>`;
    el.innerHTML = summary + [...uniq.values()].map(s => scriptBlock(s.roles.length > 3 ? `${s.roles[0]} (+${s.roles.length - 1} more)` : s.roles.join(', '), s.bytes, { info: s.info })).join('');
    el.querySelector('#n-scripts');
    document.getElementById('n-scripts').textContent = uniq.size;
  }

  // ------------------------------------------------------------------ annotated hex
  const HEX_LEGEND = [['magic', 'PSBT magic'], ['psbt-key', 'PSBT key'], ['psbt-val', 'PSBT value'], ['sep', 'map separator'], ['version', 'version'], ['marker', 'segwit marker'], ['count', 'count / length'], ['in-txid', 'prev txid'], ['in-vout', 'prev vout'], ['in-script', 'scriptSig'], ['in-seq', 'sequence'], ['out-value', 'output value'], ['out-script', 'scriptPubKey'], ['witness', 'witness'], ['locktime', 'locktime']];
  function renderHex(legendEl, infoEl, viewEl, model) {
    const bytes = model.bytes;
    const isPsbt = model.kind === 'psbt';
    legendEl.innerHTML = HEX_LEGEND.filter(([c]) => isPsbt || !['magic', 'psbt-key', 'psbt-val', 'sep'].includes(c)).map(([c, l]) => `<span style="--c:transparent"><i class="hx-${c}" style="display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px"></i>${l}</span>`).join('');
    if (bytes.length > 300000) { viewEl.innerHTML = `<span class="muted">Too large to annotate (${bytes.length} bytes).</span>`; return; }
    const segs = model.segments.slice().sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    // innermost segment per byte
    const owner = new Int32Array(bytes.length).fill(-1);
    segs.forEach((s, i) => { for (let b = s.start; b < s.end && b < bytes.length; b++) { const o = owner[b]; if (o < 0 || (segs[o].end - segs[o].start) > (s.end - s.start)) owner[b] = i; } });
    const html = [];
    let i = 0;
    while (i < bytes.length) {
      const o = owner[i];
      let j = i + 1;
      while (j < bytes.length && owner[j] === o) j++;
      const hx = hex(bytes.subarray(i, j));
      if (o < 0) html.push(`<span class="hx-unknown" data-i="-1">${hx}</span>`);
      else html.push(`<span class="hx-${segs[o].cls}" data-i="${o}">${hx}</span>`);
      i = j;
    }
    viewEl.innerHTML = html.join('');
    const show = (idx) => {
      const s = segs[idx];
      if (!s) { infoEl.innerHTML = '<span class="muted">Bytes not covered by a parsed field.</span>'; return; }
      let v = s.value;
      if (typeof v === 'bigint') v = `${v} sat (${btc(v)})`;
      else if (v instanceof Uint8Array) v = v.length ? hex(v) : '(empty)';
      else if (v === undefined) v = '';
      infoEl.innerHTML = `<b>${esc(s.label)}</b> · bytes ${s.start}–${s.end - 1} (${s.end - s.start} B)${v !== '' ? `<br>${esc(String(v))}` : ''}`;
    };
    let pinned = null;
    viewEl.onmouseover = (e) => { const t = e.target.closest('span'); if (t && pinned === null) show(+t.dataset.i); };
    viewEl.onclick = (e) => { const t = e.target.closest('span'); if (!t) return; viewEl.querySelectorAll('.pin').forEach(x => x.classList.remove('pin')); if (pinned === t) { pinned = null; } else { pinned = t; t.classList.add('pin'); } show(+t.dataset.i); };
  }

  function renderPsbtFields(el, model) {
    if (model.kind !== 'psbt') { el.innerHTML = '<p class="muted">Not a PSBT — raw transactions have no key/value maps.</p>'; return; }
    const rows = [];
    const g = model.psbt.global;
    const addRows = (scope, entries) => entries.forEach(e => rows.push(`<tr><td>${esc(scope)}</td><td class="mono">${esc(e.typeName)} <span class="muted">(0x${e.type.toString(16).padStart(2, '0')})</span></td><td class="mono">${e.keyData.length ? short(hex(e.keyData), 24, 12) : '<span class="muted">—</span>'}</td><td class="mono" title="${hex(e.value)}">${short(hex(e.value), 48, 16)}<span class="muted"> (${e.value.length} B)</span>${copyBtn(hex(e.value))}</td></tr>`));
    const gEntries = []; // reconstruct from parsed: we kept raw only for inputs/outputs; summarize global from structured data
    let gHtml = `<div class="kv" style="margin-bottom:14px">`;
    gHtml += `<div class="k">PSBT version</div><div class="v">${model.psbtVersion}</div>`;
    if (g.unsignedTx) gHtml += `<div class="k">Unsigned tx</div><div class="v">${g.unsignedTx.size} B · txid ${g.unsignedTx.txid}</div>`;
    if (g.txVersion !== undefined) gHtml += `<div class="k">Tx version (v2)</div><div class="v">${g.txVersion}</div>`;
    if (g.fallbackLocktime !== undefined) gHtml += `<div class="k">Fallback locktime</div><div class="v">${g.fallbackLocktime}</div>`;
    if (g.txModifiable !== undefined) gHtml += `<div class="k">Tx modifiable flags</div><div class="v">0x${g.txModifiable.toString(16)} (${[g.txModifiable & 1 ? 'inputs modifiable' : '', g.txModifiable & 2 ? 'outputs modifiable' : '', g.txModifiable & 4 ? 'has SIGHASH_SINGLE' : ''].filter(Boolean).join(', ') || 'none'})</div>`;
    g.xpubs.forEach((x, i) => gHtml += `<div class="k">Global xpub #${i}</div><div class="v">[${x.masterFingerprint}] ${esc(x.path)}<br>${esc(x.encoded)}${copyBtn(x.encoded)}<br><span class="muted">${esc(x.versionName)} · depth ${x.depth} · fingerprint ${x.fingerprint}</span></div>`);
    g.proprietary.forEach((p, i) => gHtml += `<div class="k">Proprietary #${i}</div><div class="v">${esc(p.identifierText || p.identifier)} sub=${p.subtype} key=${short(p.keyData, 16, 8)} value=${short(p.value, 24, 8)}</div>`);
    g.unknown.forEach((u, i) => gHtml += `<div class="k">Unknown #${i}</div><div class="v">type 0x${u.type.toString(16)} key=${short(u.key, 16, 8)} value=${short(u.value, 24, 8)}</div>`);
    gHtml += '</div>';
    model.psbt.inputs.forEach(i => addRows(`Input #${i.index}`, i.raw));
    model.psbt.outputs.forEach(o => addRows(`Output #${o.index}`, o.raw));
    el.innerHTML = gHtml + `<table class="fields"><thead><tr><th>Map</th><th>Type</th><th>Key data</th><th>Value</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
  }

  // ------------------------------------------------------------------ JSON
  function toJSON(model, a) {
    const conv = (v) => {
      if (typeof v === 'bigint') return v.toString();
      if (v instanceof Uint8Array) return hex(v);
      if (Array.isArray(v)) return v.map(conv);
      if (v && typeof v === 'object') { const o = {}; for (const [k, x] of Object.entries(v)) if (!['raw', 'bytes', 'segments', 'psbt', 'spkClass', 'layers', 'dv'].includes(k)) o[k] = conv(x); return o; }
      return v;
    };
    const out = {
      kind: model.kind, psbtVersion: model.psbtVersion, network: model.network, status: model.status, verdict: a.verdict,
      txid: model.finalTx ? model.finalTx.txid : model.tx.txid, version: model.tx.version, locktime: model.tx.locktime,
      size: model.tx.size, vsize: model.tx.vsize, weight: model.tx.weight, estimatedVsize: model.estimatedVsize,
      totalIn: model.totalIn, totalOut: model.totalOut, fee: model.fee,
      inputs: model.inputs.map(i => ({ index: i.index, txid: i.txid, vout: i.vout, sequence: i.sequence, value: i.value, address: i.address, scriptPubKey: i.utxo ? i.utxo.script : null, scriptType: i.spkClass ? i.spkClass.type : null, spendType: i.spend.type, spendLabel: i.spend.label, status: i.status, signatures: i.signatures, rawSignatures: i.rawSignatures, need: i.need, have: i.have, sighashType: i.declaredSighash, redeemScript: i.redeemScript, witnessScript: i.witnessScript, scriptSig: i.scriptSig, witness: i.witness, bip32: i.psbt && i.psbt.bip32, tapBip32: i.psbt && i.psbt.tapBip32, tapInternalKey: i.psbt && i.psbt.tapInternalKey, problems: i.problems })),
      outputs: model.outputs.map(o => ({ index: o.index, value: o.value, address: o.address, scriptPubKey: o.script, scriptType: o.type, asm: o.spkClass.asm, isChange: o.isChange, bip32: o.bip32, opReturnData: o.spkClass.data, opReturnText: o.spkClass.dataText, problems: o.problems })),
      global: model.psbt ? { xpubs: model.psbt.global.xpubs, proprietary: model.psbt.global.proprietary, unknown: model.psbt.global.unknown } : undefined,
      finalTxHex: model.finalTx ? model.finalTx.hex : undefined,
      checks: a.checks,
    };
    return JSON.stringify(conv(out), null, 2);
  }

  root.UI = { renderVerdict, renderStats, renderFlow, renderMoneyBar, renderChecks, renderInputs, renderOutputs, renderScripts, renderHex, renderPsbtFields, toJSON, esc };
})(typeof window !== 'undefined' ? window : globalThis);
