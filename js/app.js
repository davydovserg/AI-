/* AI-пульт собственника — демонстрационный фронтенд без зависимостей.
   Данные: data/month-0..3.json (fallback для file:// — data/epochs.js). */
(() => {
  "use strict";

  // ---------- Псевдо-пароль ----------
  // Хранится только SHA-256. Кириллические «о/О» приводятся к латинице, чтобы пароль
  // вводился в любой раскладке. Это защита от случайного просмотра, а не безопасность.
  const PASS_HASH = "02b61715919e95d316afe69f5ce80fcad5846016b6473f0cb98c5e7bdb27d28b";
  const AUTH_KEY = "aipult.auth";
  const STATE_KEY = "aipult.decisions.v1";
  const EPOCH_KEY = "aipult.epoch";

  function sha256(str) {
    const bytes = new TextEncoder().encode(str);
    const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const len = bytes.length;
    const total = ((len + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(total);
    buf.set(bytes);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 4, len * 8);
    dv.setUint32(total - 8, Math.floor(len / 0x20000000));
    const W = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let o = 0; o < total; o += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
        const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    return H.map((x) => x.toString(16).padStart(8, "0")).join("");
  }
  const normalizePass = (s) => s.trim().replace(/о/g, "o").replace(/О/g, "O");

  // ---------- Безопасное хранилище ----------
  const store = {
    get(k, s = localStorage) { try { return s.getItem(k); } catch { return null; } },
    set(k, v, s = localStorage) { try { s.setItem(k, v); } catch { /* приватный режим */ } },
    del(k, s = localStorage) { try { s.removeItem(k); } catch { /* */ } },
  };

  // ---------- Утилиты ----------
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (v, d = 1) => (v == null ? "—" : Number(v).toLocaleString("ru-RU", { maximumFractionDigits: d }));
  const signed = (v, d = 1) => (v > 0 ? "+" : v < 0 ? "−" : "±") + num(Math.abs(v), d);
  const fmtDate = (iso) => new Date(iso + "T00:00:00").toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric" });
  let toastTimer;
  function toast(text) {
    const t = $("#toast");
    t.textContent = text;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.hidden = true), 3200);
  }

  // ---------- Состояние ----------
  let EPOCHS = [];
  let cur = 0;
  let decisionState = {};

  const allDecisions = () => EPOCHS.flatMap((e) => e.decisions.map((d) => ({ ...d, epoch: e.epoch })));
  const statusOf = (d) => decisionState[d.id] ?? d.scenario;
  const isAccepted = (d) => statusOf(d) === "accepted";
  const changedFromScenario = () => allDecisions().some((d) => statusOf(d) !== d.scenario);

  // Значение KPI в эпохе e с учётом решений, которые пользователь изменил в прошлых эпохах.
  // JSON эпохи e уже содержит эффект базового сценария; здесь добавляется только разница.
  function kpiValue(e, id) {
    const base = EPOCHS[e].kpis.find((k) => k.id === id)?.value;
    if (base == null) return null;
    let v = base;
    for (const d of allDecisions()) {
      if (d.epoch >= e || !d.impact || d.impact[id] == null) continue;
      const diff = (isAccepted(d) ? 1 : 0) - (d.scenario === "accepted" ? 1 : 0);
      v += diff * d.impact[id];
    }
    if (id === "tax_debt" || id === "risk_rub" || id === "overdue_ar") v = Math.max(0, v);
    return Math.round(v * 10) / 10;
  }
  // Прогноз на следующий месяц по решениям текущей эпохи
  function kpiProjection(e, id) {
    const v = kpiValue(e, id);
    if (v == null) return null;
    let delta = 0;
    for (const d of EPOCHS[e].decisions) if (isAccepted(d) && d.impact?.[id] != null) delta += d.impact[id];
    return delta ? { delta, value: Math.round((v + delta) * 10) / 10 } : null;
  }
  function kpiStatus(k, v) {
    if (v == null) return "na";
    const t = k.target;
    if (k.better === "lower") {
      if (v <= t) return "ok";
      return v <= (t === 0 ? 1 : t * 1.5) ? "warn" : "bad";
    }
    if (v >= t) return "ok";
    return v >= t * 0.8 ? "warn" : "bad";
  }
  const effectTotal = (e) => allDecisions().filter((d) => d.epoch <= e && isAccepted(d)).reduce((s, d) => s + (d.effectRub || 0), 0);
  const queue = (e) => EPOCHS[e].decisions.filter((d) => ["pending", "deferred"].includes(statusOf(d)));

  // ---------- Загрузка данных ----------
  async function loadEpochs() {
    try {
      const res = await Promise.all([0, 1, 2, 3].map((i) => fetch(`data/month-${i}.json`, { cache: "no-store" }).then((r) => {
        if (!r.ok) throw new Error(r.status);
        return r.json();
      })));
      return res;
    } catch {
      // file:// — fetch недоступен, подключаем бандл
      await new Promise((ok, fail) => {
        const s = document.createElement("script");
        s.src = "data/epochs.js";
        s.onload = ok;
        s.onerror = fail;
        document.head.appendChild(s);
      });
      return window.EPOCHS;
    }
  }

  // ---------- Рендер: шапка и hero ----------
  const STATE_LABEL = { offline: ["Пульт не подключён", "grey"], audit: ["Аудит", "yellow"], integrating: ["Интеграция данных", "yellow"], live: ["Пульт в работе", "green"] };

  function renderEpochs() {
    $("#epochs").innerHTML = EPOCHS.map((e) => `
      <button data-epoch="${e.epoch}" class="${e.epoch === cur ? "is-active" : ""}" aria-pressed="${e.epoch === cur}">
        <b>${esc(e.code)}</b><small>День ${e.day} · ${fmtDate(e.date)}</small>
      </button>`).join("");
  }

  function renderHero() {
    const e = EPOCHS[cur];
    const [stLabel, stColor] = STATE_LABEL[e.systemState];
    const cps = { 4: "КТ1", 8: "КТ2", 12: "КТ3" };
    $("#hero").innerHTML = `
      <div class="hero__num">${esc(e.code)}</div>
      <div>
        <div class="hero__kicker">
          <span>${esc(e.title)}</span>
          <span class="state"><i class="dot dot--${stColor}"></i>${stLabel}</span>
          <span class="muted">День ${e.day} · неделя ${e.week} из 13</span>
        </div>
        <h2>${esc(e.headline)}</h2>
        <p>${esc(e.summary)}</p>
        <div class="timeline">${Array.from({ length: 13 }, (_, i) => `<span class="${i + 1 < e.week ? "done" : i + 1 === e.week ? "now" : ""}"></span>`).join("")}</div>
        <div class="timeline__legend">${Array.from({ length: 13 }, (_, i) => `<span class="${cps[i + 1] ? "cp" : ""}">${cps[i + 1] || "н" + (i + 1)}</span>`).join("")}</div>
      </div>`;
    $("#groupName").textContent = e.meta.group;
    $("#sources").textContent = "Источники: " + e.meta.sources;
  }

  // ---------- Пульт ----------
  function kpiCard(k) {
    const v = kpiValue(cur, k.id);
    const st = kpiStatus(k, v);
    const prev = cur > 0 ? kpiValue(cur - 1, k.id) : null;
    let delta = "";
    if (v != null && prev != null && v !== prev) {
      const good = k.better === "lower" ? v < prev : v > prev;
      delta = `<span class="delta ${good ? "delta--good" : "delta--bad"}">${signed(v - prev)} к ${EPOCHS[cur - 1].code}</span>`;
    }
    const proj = kpiProjection(cur, k.id);
    const base = EPOCHS[cur].kpis.find((x) => x.id === k.id).value;
    const adjusted = v != null && base != null && v !== base;
    return `
      <div class="kpi kpi--${st}">
        <div class="kpi__label">${esc(k.label)} ${k.model ? '<span class="tag tag--model">модель</span>' : ""}</div>
        <div class="kpi__value ${v == null ? "kpi__value--na" : ""}">${v == null ? "нет данных" : num(v)}${v == null ? "" : `<small>${esc(k.unit)}</small>`}</div>
        <div class="kpi__row"><span>цель ${num(k.target)} ${esc(k.unit)}</span>${delta}</div>
        ${adjusted ? `<div class="kpi__proj">⟲ ваши решения изменили значение (база: ${num(base)})</div>` : ""}
        ${proj ? `<div class="kpi__proj">→ после решений месяца: ${num(proj.value)} (${signed(proj.delta)})</div>` : ""}
        ${k.note ? `<div class="kpi__note">${esc(k.note)}</div>` : ""}
      </div>`;
  }

  function cashChart(cf) {
    if (!cf) return "";
    const useAlt = cf.alt && EPOCHS[cur].realized.some((r) => {
      const d = allDecisions().find((x) => x.id === r.id);
      return d && ["d08", "d09"].includes(d.id) && !isAccepted(d);
    });
    const main = useAlt ? cf.alt : cf.weeks;
    const other = cf.alt ? (useAlt ? cf.weeks : cf.alt) : null;
    const W = 640, H = 240, pl = 44, pr = 12, pt = 14, pb = 28;
    const all = [...cf.weeks, ...(cf.alt || []), 0, cf.threshold];
    const max = Math.ceil(Math.max(...all) / 10) * 10;
    const min = Math.floor(Math.min(...all) / 10) * 10;
    const x = (i) => pl + (i * (W - pl - pr)) / (main.length - 1);
    const y = (v) => pt + ((max - v) * (H - pt - pb)) / (max - min);
    const path = (arr) => arr.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
    let grid = "";
    for (let v = min; v <= max; v += 10) grid += `<line class="grid-line" x1="${pl}" x2="${W - pr}" y1="${y(v)}" y2="${y(v)}"/><text x="${pl - 8}" y="${y(v) + 4}" text-anchor="end">${v}</text>`;
    const labels = main.map((_, i) => `<text x="${x(i)}" y="${H - 8}" text-anchor="middle">${i + 1}</text>`).join("");
    const pts = main.map((v, i) => `<circle class="pt ${v < 0 ? "pt--neg" : ""}" cx="${x(i)}" cy="${y(v)}" r="${v < 0 ? 5 : 3}"><title>Неделя ${i + 1}: ${num(v)} млн ₽</title></circle>`).join("");
    return `
      <svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Прогноз остатка денег группы на 13 недель">
        <defs><linearGradient id="gradA" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#4cc9f0" stop-opacity=".28"/><stop offset="1" stop-color="#4cc9f0" stop-opacity="0"/></linearGradient></defs>
        ${grid}
        <line class="zero" x1="${pl}" x2="${W - pr}" y1="${y(0)}" y2="${y(0)}"/>
        <line class="threshold" x1="${pl}" x2="${W - pr}" y1="${y(cf.threshold)}" y2="${y(cf.threshold)}"/>
        <path class="area" d="${path(main)}L${x(main.length - 1)},${y(min)}L${x(0)},${y(min)}Z"/>
        ${other ? `<path class="line line--alt" d="${path(other)}"/>` : ""}
        <path class="line" d="${path(main)}"/>
        ${pts}${labels}
      </svg>
      <div class="legend">
        <span><i></i>${useAlt ? "Ваш сценарий (решения отклонены)" : "Прогноз остатка, млн ₽"}</span>
        ${other ? `<span><i class="alt"></i>${useAlt ? "Базовый сценарий (решения приняты)" : esc(cf.altLabel)}</span>` : ""}
        <span><i class="thr"></i>Порог безопасности ${cf.threshold} млн ₽</span>
      </div>`;
  }

  function renderCockpit() {
    const e = EPOCHS[cur];
    const brief = e.brief.map((b) => `
      <div class="brief__item brief__item--${b.level}">
        <div>
          <div class="brief__title">${esc(b.title)}</div>
          <div class="brief__meta">Источник: ${esc(b.source)}${b.action && b.action !== "—" ? ` · <b>${esc(b.action)}</b>` : ""}</div>
        </div>
        <div class="brief__rub">${b.rub != null ? num(b.rub) + "<small>млн ₽</small>" : ""}</div>
      </div>`).join("");

    const tg = e.telegram.map((m, i) => `<div class="msg msg--${m.from}" style="animation-delay:${i * 0.45}s">${esc(m.text)}<time>${esc(m.time)}</time></div>`).join("");

    const feed = e.riskFeed.map((r) => {
      const color = { critical: "red", warn: "yellow", ok: "green", info: "" }[r.level] || "";
      return `<div class="feed__item"><span class="feed__date">${esc(r.date)}</span><i class="dot ${color ? "dot--" + color : ""}"></i>
        <div><div class="feed__src">${esc(r.source)} · ${esc(r.entity)} ${r.model ? '<span class="tag tag--model">модель</span>' : ""}</div><div class="feed__text">${esc(r.text)}</div></div></div>`;
    }).join("");

    $("#tab-cockpit").innerHTML = `
      <div class="grid grid--cockpit">
        <div class="card">
          <div class="card__head"><h3>Что требует внимания</h3><span class="label">по деньгам под риском</span></div>
          <div class="brief">${brief}</div>
        </div>
        <div class="card">
          <div class="card__head"><h3>Telegram-бот собственника</h3><span class="label">${e.systemState === "live" ? "в работе" : "тест"}</span></div>
          <div class="phone"><div class="phone__screen">
            <div class="phone__bar"><div class="logo"><span>П</span><i></i></div><div><b>AI-пульт</b><small>${e.systemState === "offline" ? "подключается…" : "онлайн"}</small></div></div>
            <div class="chat">${tg}</div>
          </div></div>
        </div>
      </div>

      <div class="section-title"><h3>Ключевые показатели</h3><span class="muted">цвет — расстояние до цели этапа</span></div>
      <div class="kpis">${e.kpis.map(kpiCard).join("")}</div>

      <div class="grid grid--2" style="margin-top:16px">
        <div class="card">
          <div class="card__head"><h3>Платёжный календарь группы · 13 недель</h3>${e.cashForecast ? '<span class="tag tag--model">модель</span>' : ""}</div>
          ${e.cashForecast ? cashChart(e.cashForecast) : `<div class="empty">Данные 1С не подключены.<br>Сейчас остаток денег — ручная оценка финслужбы раз в неделю.<br><b>Появится на дне 60.</b></div>`}
        </div>
        <div class="card">
          <div class="card__head"><h3>Риск-радар</h3><span class="label">ЕГРЮЛ · ФНС · КАД · ФССП · ЕИС · ЕФРСБ</span></div>
          <div class="feed">${feed}</div>
        </div>
      </div>`;
  }

  // ---------- Решения ----------
  const STATUS_TEXT = { accepted: "Принято", rejected: "Отклонено", deferred: "Отложено", pending: "Ждёт решения" };
  const kpiShort = (id) => EPOCHS[0].kpis.find((k) => k.id === id);

  function renderDecisions() {
    const e = EPOCHS[cur];
    const q = queue(cur);
    const accepted = allDecisions().filter((d) => d.epoch <= cur && isAccepted(d)).length;
    const cards = e.decisions.map((d) => {
      const st = statusOf(d);
      const impacts = Object.entries(d.impact || {}).filter(([, v]) => v).map(([id, v]) => {
        const k = kpiShort(id);
        const good = k.better === "lower" ? v < 0 : v > 0;
        return `<span class="tag ${good ? "tag--ok" : "tag--bad"}">${esc(k.label)}: ${signed(v)} ${esc(k.unit)}</span>`;
      }).join("");
      return `
        <article class="dec dec--${st}">
          <div class="dec__head">
            <div><span class="dec__id">${d.id.toUpperCase()}</span><span class="dec__title">${esc(d.title)}</span></div>
            <div style="display:flex;gap:6px;flex-wrap:wrap"><span class="tag tag--accent">${esc(d.area)}</span>${d.model ? '<span class="tag tag--model">модель</span>' : ""}</div>
          </div>
          <dl class="dec__body">
            <dt>Сигнал</dt><dd>${esc(d.signal)}</dd>
            <dt>Расчёт</dt><dd>${esc(d.calc)}</dd>
            <dt>Варианты</dt><dd><ol>${d.options.map((o) => `<li>${esc(o)}</li>`).join("")}</ol></dd>
            <dt>Рекомендация</dt><dd class="dec__reco">${esc(d.recommendation)}</dd>
            <dt>Уверенность</dt><dd>${esc(d.confidence)} · источник: ${esc(d.source)}</dd>
            ${impacts || d.effectRub ? `<dt>Эффект</dt><dd><div class="impact">${d.effectRub ? `<span class="tag tag--ok">≈ ${num(d.effectRub)} млн ₽/год</span>` : ""}${impacts}</div></dd>` : ""}
          </dl>
          <div class="dec__foot">
            <span class="label">Решение собственника</span>
            <div class="seg" data-dec="${d.id}">
              <button data-set="accepted" class="${st === "accepted" ? "on-accepted" : ""}">Да</button>
              <button data-set="deferred" class="${st === "deferred" || st === "pending" ? "on-" + st : ""}">Отложить</button>
              <button data-set="rejected" class="${st === "rejected" ? "on-rejected" : ""}">Нет</button>
            </div>
            <span class="spacer"></span>
            <span class="muted" style="font-size:12px">${STATUS_TEXT[st]}${st !== d.scenario ? " · изменено вами" : ""}</span>
          </div>
        </article>`;
    }).join("");

    const realized = e.realized.length ? e.realized.map((r) => {
      const d = allDecisions().find((x) => x.id === r.id);
      const off = d && !isAccepted(d);
      return `<div class="realized__item ${off ? "realized__item--off" : ""}">
        <i class="dot ${off ? "dot--red" : "dot--green"}" style="margin-top:6px"></i>
        <div><div class="realized__t">${r.id.toUpperCase()} · ${esc(r.title)}</div>
        <div class="realized__e">${off ? "В вашем сценарии решение не принято — эффект не наступил." : esc(r.effect)}</div></div></div>`;
    }).join("") : `<div class="empty">Это первый месяц — прошлых решений ещё нет.</div>`;

    $("#tab-decisions").innerHTML = `
      <div class="dec-summary">
        <div class="stat"><div class="label">Ждут решения собственника</div><div class="stat__value">${q.length}<small>в ${esc(e.code)}</small></div></div>
        <div class="stat"><div class="label">Принято решений к ${esc(e.code)}</div><div class="stat__value">${accepted}</div></div>
        <div class="stat"><div class="label">Эффект принятых решений</div><div class="stat__value">${num(effectTotal(cur))}<small>млн ₽/год · модель</small></div></div>
      </div>
      <p class="muted" style="margin-top:0">Каждый совет пульта оформлен одинаково: сигнал → расчёт → варианты → рекомендация → уверенность.
      Измените решение — и увидите, как сдвинутся показатели в следующих месяцах (переключите эпоху вверху).</p>
      <div class="decisions">${cards}</div>
      <div class="section-title"><h3>Эффект прошлых решений в этом месяце</h3></div>
      <div class="realized">${realized}</div>`;
  }

  // ---------- Как работает система ----------
  const ST_TEXT = { none: "НЕТ", mapped: "ОПИСАНО", testing: "ТЕСТ", live: "ОНЛАЙН" };
  const ST_COLOR = { none: "#5c6780", mapped: "#4cc9f0", testing: "#f5a524", live: "#3ccb7f" };

  function renderSystem() {
    const e = EPOCHS[cur];
    const by = (g) => e.integrations.filter((i) => i.group === g);
    const get = (id) => e.integrations.find((i) => i.id === id);
    const srcs = [...by("internal"), ...by("external")];
    const W = 1000, rowH = 34, nodeH = 26, nodeW = 200, x0 = 10, top = 40;
    const ys = srcs.map((s, i) => top + i * rowH + (s.group === "external" ? 26 : 0));
    const H = ys[ys.length - 1] + nodeH + 20;
    const hub = { x: 400, w: 190, h: 82 };
    const dwh = get("dwh"), llm = get("llm");
    const dwhY = H / 2 - hub.h / 2;
    const llmX = 650;
    const outs = by("output");
    const outX = 840, outW = 150;
    const outYs = outs.map((_, i) => H / 2 - 70 + i * 60);
    const linkCls = (st) => (st === "live" ? "link link--live" : st === "testing" ? "link link--testing" : "link");
    const curve = (x1, y1, x2, y2) => `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`;

    let links = srcs.map((s, i) => `<path class="${linkCls(s.status)}" d="${curve(x0 + nodeW, ys[i] + nodeH / 2, hub.x, dwhY + hub.h / 2)}"/>`).join("");
    links += `<path class="${linkCls(dwh.status === "live" && llm.status !== "none" ? llm.status : "none")}" d="M${hub.x + hub.w},${dwhY + hub.h / 2} L${llmX},${dwhY + hub.h / 2}"/>`;
    links += outs.map((o, i) => `<path class="${linkCls(o.status)}" d="${curve(llmX + hub.w - 40, dwhY + hub.h / 2, outX, outYs[i] + 18)}"/>`).join("");
    // Журнал решений: обратная связь от собственника в ИИ-слой
    const jY = dwhY + hub.h + 50;
    links += `<path class="${linkCls(e.epoch >= 3 ? "live" : e.epoch >= 2 ? "testing" : "none")}" d="${curve(outX, outYs[0] + 18, llmX + 75, jY + 20)}"/>`;

    const node = (s, y) => `
      <g class="node node--${s.status}">
        <rect x="${x0}" y="${y}" width="${nodeW}" height="${nodeH}"></rect>
        <circle cx="${x0 + 14}" cy="${y + nodeH / 2}" r="4" fill="${ST_COLOR[s.status]}"></circle>
        <text x="${x0 + 26}" y="${y + 17}">${esc(s.name)}</text>
        <text class="st" x="${x0 + nodeW - 8}" y="${y + 16}" text-anchor="end" fill="${ST_COLOR[s.status]}">${ST_TEXT[s.status]}</text>
        ${s.note ? `<title>${esc(s.note)}</title>` : ""}
      </g>`;
    const hubBox = (x, y, w, h, title, sub, st) => `
      <g class="hub ${st === "none" || st === "mapped" ? "hub--off" : ""}">
        <rect x="${x}" y="${y}" width="${w}" height="${h}"></rect>
        <text x="${x + 16}" y="${y + 28}">${title}</text>
        <text class="sub" x="${x + 16}" y="${y + 48}">${sub}</text>
        <text class="sub" x="${x + 16}" y="${y + h - 10}" style="fill:${ST_COLOR[st]};font-weight:700;letter-spacing:.08em">● ${ST_TEXT[st]}</text>
      </g>`;
    const outNode = (o, y) => `
      <g class="node node--${o.status}">
        <rect x="${outX}" y="${y}" width="${outW}" height="36"></rect>
        <circle cx="${outX + 14}" cy="${y + 18}" r="4" fill="${ST_COLOR[o.status]}"></circle>
        <text x="${outX + 26}" y="${y + 22}">${esc(o.name)}</text>
      </g>`;

    const svg = `
      <svg class="flow" viewBox="0 0 ${W} ${H}" role="img" aria-label="Схема потоков данных AI-пульта">
        <text class="col-title" x="${x0}" y="${top - 12}">Внутренние системы</text>
        <text class="col-title" x="${x0}" y="${ys[by("internal").length] - 8}">Внешние источники</text>
        <text class="col-title" x="${hub.x}" y="${dwhY - 14}">Ядро</text>
        <text class="col-title" x="${outX}" y="${outYs[0] - 14}">Собственник</text>
        ${links}
        ${srcs.map((s, i) => node(s, ys[i])).join("")}
        ${hubBox(hub.x, dwhY, hub.w, hub.h, "Хранилище данных", "граф группы · справочники", dwh.status)}
        ${hubBox(llmX, dwhY, hub.w - 40, hub.h, "ИИ-слой", "правила · RAG · агенты", llm.status)}
        ${hubBox(llmX, jY, hub.w - 40, 74, "Журнал решений", "память на 20 лет", e.epoch >= 3 ? "live" : e.epoch >= 2 ? "testing" : "none")}
        ${outs.map((o, i) => outNode(o, outYs[i])).join("")}
      </svg>`;

    const steps = [
      ["Сигнал", "Что изменилось: факт, источник, дата"],
      ["Связь", "Какие юрлица, контракты и деньги затронуты"],
      ["Расчёт", "Эффект в ₽: база, пессимизм, оптимизм"],
      ["Варианты", "2–3 действия и цена бездействия"],
      ["Рекомендация", "Что делать, кто, до какого срока"],
      ["Уверенность", "Высокая / средняя / низкая и чего не хватает"],
      ["Прецедент", "Похожие решения из журнала и итог"],
    ].map(([t, p], i) => `<div class="step"><b>${i + 1}</b><span>${t}</span><p>${p}</p></div>`).join("");

    const live = e.integrations.filter((i) => i.status === "live").length;
    $("#tab-system").innerHTML = `
      <div class="card">
        <div class="card__head"><h3>Потоки данных в ${esc(e.code)}</h3><span class="label">онлайн: ${live} из ${e.integrations.length}</span></div>
        ${svg}
        <div class="legend-flow">
          <span><i style="border-color:${ST_COLOR.live}"></i>Онлайн</span>
          <span><i style="border-color:${ST_COLOR.testing}"></i>Тест</span>
          <span><i style="border-color:${ST_COLOR.mapped};border-style:dashed"></i>Описано в аудите</span>
          <span><i style="border-color:${ST_COLOR.none}"></i>Не подключено</span>
          <span>Наведите на узел — подробности</span>
        </div>
      </div>
      <div class="section-title"><h3>Как пульт формулирует совет</h3><span class="muted">единый стандарт для каждого решения</span></div>
      <div class="steps">${steps}</div>
      <div class="grid grid--3" style="margin-top:16px">
        <div class="card"><div class="label">Принцип 1</div><h3 style="margin:6px 0">Цифры только из данных</h3><p class="muted" style="margin:0">ИИ не придумывает числа: у каждой цифры есть источник — 1С, банк или реестр.</p></div>
        <div class="card"><div class="label">Принцип 2</div><h3 style="margin:6px 0">Деньги — только через человека</h3><p class="muted" style="margin:0">Пульт рекомендует и ставит задачи, но платежи без подтверждения собственника не проводит.</p></div>
        <div class="card"><div class="label">Принцип 3</div><h3 style="margin:6px 0">Данные принадлежат группе</h3><p class="muted" style="margin:0">LLM — сменный двигатель. Граф группы, журнал решений и принципы остаются на 20 лет.</p></div>
      </div>`;
  }

  // ---------- Группа ----------
  const LVL = ["не подключено", "описано в аудите", "подключено частично", "онлайн"];
  function renderGroup() {
    const e = EPOCHS[cur];
    const dirs = e.meta.directions;
    const sumRev = e.companies.reduce((s, c) => s + (c.revenue || 0), 0);
    const html = Object.entries(dirs).map(([key, title]) => {
      const list = e.companies.filter((c) => c.dir === key);
      return `<div class="dir">
        <div class="dir__title"><h4>${esc(title)}</h4><span class="muted">${list.length} юрлиц</span></div>
        <div class="cos">${list.map((c) => `
          <div class="co">
            <div class="co__head"><i class="dot dot--${c.status}"></i><span class="co__name">${esc(c.name)}</span></div>
            <div class="co__city">${esc(c.city)} · ИНН ${esc(c.inn)} · ${esc(c.role)}</div>
            <div class="co__rev">${c.revenue == null ? "—" : num(c.revenue)} <small>млн ₽ выручка 2025</small></div>
            <div class="co__facts">${esc(c.facts)}</div>
            <div class="levels">${[1, 2, 3].map((l) => `<span class="${c.dataLevel >= l ? "on" : ""}"></span>`).join("")}</div>
            <div class="co__lvl">Данные в пульте: ${LVL[c.dataLevel]}</div>
            ${c.note ? `<div class="co__note">${esc(c.note)}</div>` : ""}
          </div>`).join("")}</div>
      </div>`;
    }).join("");
    $("#tab-group").innerHTML = `
      <div class="dec-summary">
        <div class="stat"><div class="label">Юрлиц в периметре</div><div class="stat__value">${e.companies.length}<small>+ ИП (мясное производство, с 2003)</small></div></div>
        <div class="stat"><div class="label">Выручка известных компаний, 2025</div><div class="stat__value">${num(sumRev)}<small>млн ₽ · открытые данные</small></div></div>
        <div class="stat"><div class="label">Подключено к пульту</div><div class="stat__value">${e.companies.filter((c) => c.dataLevel >= 2).length}<small>из ${e.companies.length}</small></div></div>
      </div>
      ${html}
      <p class="muted" style="font-size:12px">Структура и выручка — по открытым реестрам (ЕГРЮЛ, ФНС, ЕИС). Статусы и уровень подключения — сценарий проекта.</p>`;
  }

  // ---------- Проект 90 дней ----------
  function renderProject() {
    const e = EPOCHS[cur];
    const p = e.project;
    const phases = p.phases.map((f) => `
      <div class="phase">
        <div class="phase__name">${esc(f.name)}<small>недели ${esc(f.weeks)}</small></div>
        <div class="bar ${f.progress === 100 ? "bar--ok" : ""}"><i style="width:${f.progress}%"></i></div>
        <div class="phase__pct">${f.progress}%</div>
      </div>`).join("");
    const tasks = (arr) => `<ul class="tasks">${arr.map((t) => `<li class="${t.done ? "done" : ""}"><span class="chk">${t.done ? "✓" : ""}</span><span>${esc(t.text)}</span></li>`).join("")}</ul>`;
    const icon = { pass: "✓", partial: "!", fail: "×", pending: "" };
    const cps = p.checkpoints.map((c) => {
      const passed = c.criteria.filter((x) => x.status === "pass").length;
      const started = c.criteria.some((x) => x.status !== "pending");
      const tag = !started ? '<span class="tag">впереди</span>' : passed === c.criteria.length ? '<span class="tag tag--ok">пройдена</span>' : '<span class="tag tag--warn">с замечанием</span>';
      return `<div class="card">
        <div class="cp__head"><div><div class="label">${esc(c.name)}</div><div class="cp__day">День ${c.day} <small>${started ? `${passed} из ${c.criteria.length}` : ""}</small></div></div>${tag}</div>
        <ul class="crit">${c.criteria.map((x) => `<li><span class="ic ic--${x.status}">${icon[x.status]}</span><span>${esc(x.text)}${x.fact ? `<small>${esc(x.fact)}</small>` : ""}</span></li>`).join("")}</ul>
      </div>`;
    }).join("");
    const top = e.top20.length ? `
      <div class="card table-wrap">
        <table class="table">
          <thead><tr><th>#</th><th>Кейс</th><th>Где</th><th style="text-align:right">Эффект, млн ₽/год</th><th>Балл</th><th>Статус</th></tr></thead>
          <tbody>${e.top20.map((t) => `<tr class="${t.status === "mvp" ? "mvp" : ""}">
            <td class="num">${t.n}</td><td>${esc(t.title)}</td><td class="muted">${esc(t.area)}</td><td class="num">${num(t.effect)}</td>
            <td class="num"><span class="score"><i style="width:${(t.score / 5) * 100}%"></i></span>${num(t.score)}</td>
            <td>${t.status === "mvp" ? '<span class="tag tag--accent">MVP</span>' : t.status === "stage2" ? '<span class="tag">этап 2</span>' : '<span class="tag">бэклог</span>'}</td></tr>`).join("")}</tbody>
        </table>
        <p class="muted" style="font-size:12px;margin:10px 0 0">Эффект — оценка аудита <span class="tag tag--model">модель</span>. Балл: эффект 40%, срочность 20%, готовность данных 20%, простота 20%.</p>
      </div>` : `<div class="empty">TOP-20 появится по итогам аудита (день 30).</div>`;
    const ai = e.ai ? `
      <div class="dec-summary" style="margin-top:16px">
        <div class="stat"><div class="label">Ответов ИИ</div><div class="stat__value">${num(e.ai.answers, 0)}</div></div>
        <div class="stat"><div class="label">С ошибкой</div><div class="stat__value">${num(e.ai.wrong, 0)}<small>${num((e.ai.wrong / e.ai.answers) * 100)}%</small></div></div>
        <div class="stat"><div class="label">Выдуманных цифр</div><div class="stat__value">${e.ai.invented}<small>${e.ai.useful ? `полезность ${e.ai.useful}%` : "пилот ещё не начат"}</small></div></div>
      </div>` : "";

    $("#tab-project").innerHTML = `
      <div class="card">
        <div class="card__head"><h3>Фазы этапа 1</h3><span class="label">неделя ${e.week} из 13</span></div>
        <div class="phases">${phases}</div>
      </div>
      <div class="section-title"><h3>Разделение работы в ${esc(e.code)}</h3></div>
      <div class="roles">
        <div class="card">
          <div class="role__head"><div class="role__badge">Р</div><div><h3>Руководитель AI-трансформации</h3><div class="role__desc">Бизнес-результат: что делаем, зачем и сколько это даёт в ₽</div></div></div>
          ${tasks(p.tasks.R)}
        </div>
        <div class="card">
          <div class="role__head"><div class="role__badge role__badge--t">Т</div><div><h3>Технический ассистент</h3><div class="role__desc">Исполнение: чтобы данные текли, а сценарии работали</div></div></div>
          ${tasks(p.tasks.T)}
        </div>
      </div>
      <div class="section-title"><h3>Контрольные точки: проверяет собственник</h3><span class="muted">на каждой — решение «продолжаем / корректируем / стоп»</span></div>
      <div class="cps">${cps}</div>
      <div class="section-title"><h3>Журнал качества ИИ</h3></div>
      ${ai || `<div class="empty">ИИ-слой ещё не отвечает на вопросы — журнал начнётся на неделе 6.</div>`}
      <div class="section-title"><h3>TOP-20 AI-кейсов</h3></div>
      ${top}`;
  }

  // ---------- Эффект ----------
  function renderEffect() {
    const sparks = EPOCHS[0].kpis.map((k) => {
      const vals = EPOCHS.map((_, i) => kpiValue(i, k.id));
      const known = vals.filter((v) => v != null);
      const W = 260, H = 70, p = 10;
      const lo = Math.min(...known, k.target), hi = Math.max(...known, k.target);
      const span = hi - lo || 1;
      const x = (i) => p + (i * (W - 2 * p)) / 3;
      const y = (v) => H - 14 - ((v - lo) / span) * (H - 28);
      let d = "";
      vals.forEach((v, i) => { if (v != null) d += `${d ? "L" : "M"}${x(i)},${y(v)}`; });
      const first = known[0], v = vals[cur];
      const good = first != null && v != null && (k.better === "lower" ? v < first : v > first);
      return `<div class="spark">
        <div class="spark__head"><span>${esc(k.label)}</span>${k.model ? '<span class="tag tag--model">модель</span>' : ""}</div>
        <div class="spark__val">${v == null ? "—" : num(v)} <small class="muted" style="font:500 12px var(--font)">${esc(k.unit)}</small>
          ${first != null && v != null && v !== first ? `<span class="delta ${good ? "delta--good" : "delta--bad"}">${signed(v - first)} с начала</span>` : ""}</div>
        <svg viewBox="0 0 ${W} ${H}">
          <line class="t" x1="${p}" x2="${W - p}" y1="${y(k.target)}" y2="${y(k.target)}"/>
          <path class="l" d="${d}"/>
          ${vals.map((vv, i) => (vv == null ? "" : `<circle class="${i === cur ? "cur" : ""}" cx="${x(i)}" cy="${y(vv)}" r="${i === cur ? 4.5 : 3}"><title>${EPOCHS[i].code}: ${num(vv)}</title></circle>`)).join("")}
          ${EPOCHS.map((e2, i) => `<text x="${x(i)}" y="${H - 1}" text-anchor="middle">${e2.code}</text>`).join("")}
        </svg>
      </div>`;
    }).join("");

    const rows = EPOCHS[0].kpis.map((k) => {
      const v0 = kpiValue(0, k.id) ?? kpiValue(1, k.id);
      const v3 = kpiValue(3, k.id);
      const ok = v3 != null && (k.better === "lower" ? v3 <= k.target : v3 >= k.target);
      return `<tr><td>${esc(k.label)}</td><td class="num">${num(v0)}</td><td class="num">${num(v3)}</td><td class="num">${num(k.target)}</td><td class="muted">${esc(k.unit)}</td>
        <td>${v3 == null ? "" : ok ? '<span class="tag tag--ok">цель достигнута</span>' : '<span class="tag tag--warn">в работе</span>'}</td></tr>`;
    }).join("");

    $("#tab-effect").innerHTML = `
      <div class="dec-summary">
        <div class="stat"><div class="label">Эффект принятых решений к ${esc(EPOCHS[cur].code)}</div><div class="stat__value">${num(effectTotal(cur))}<small>млн ₽/год · модель</small></div></div>
        <div class="stat"><div class="label">Задержка «сигнал → решение»</div><div class="stat__value">${cur >= 3 ? "2" : cur >= 2 ? "7" : "365+"}<small>дней (до пульта — 12–24 мес.)</small></div></div>
        <div class="stat"><div class="label">Решений в журнале</div><div class="stat__value">${allDecisions().filter((d) => d.epoch <= cur && statusOf(d) !== "pending").length}<small>с обоснованием</small></div></div>
      </div>
      <div class="section-title"><h3>Динамика показателей по эпохам</h3><span class="muted">пунктир — цель этапа · учитываются ваши решения</span></div>
      <div class="spark-grid">${sparks}</div>
      <div class="section-title"><h3>До и после: отчёт собственнику</h3><span class="muted">«до» — первый месяц с данными</span></div>
      <div class="card table-wrap"><table class="table">
        <thead><tr><th>Показатель</th><th style="text-align:right">До</th><th style="text-align:right">День 90</th><th style="text-align:right">Цель</th><th>Ед.</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
  }

  // ---------- Общий рендер и события ----------
  function render() {
    renderEpochs();
    renderHero();
    renderCockpit();
    renderDecisions();
    renderSystem();
    renderGroup();
    renderProject();
    renderEffect();
    const q = queue(cur).length;
    const b = $("#queueBadge");
    b.hidden = !q;
    b.textContent = q;
    $("#resetBtn").hidden = !changedFromScenario();
  }

  function setEpoch(i) {
    cur = Math.max(0, Math.min(EPOCHS.length - 1, i));
    store.set(EPOCH_KEY, String(cur));
    render();
  }

  function bind() {
    $("#epochs").addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-epoch]");
      if (btn) setEpoch(+btn.dataset.epoch);
    });
    $("#tabs").addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-tab]");
      if (!btn) return;
      document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("is-active", b === btn));
      document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t.id === "tab-" + btn.dataset.tab));
    });
    $("#tab-decisions").addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-set]");
      if (!btn) return;
      const id = btn.parentElement.dataset.dec;
      const d = allDecisions().find((x) => x.id === id);
      if (btn.dataset.set === d.scenario) delete decisionState[id];
      else decisionState[id] = btn.dataset.set;
      store.set(STATE_KEY, JSON.stringify(decisionState));
      render();
      const hasImpact = Object.values(d.impact || {}).some(Boolean);
      toast(`${id.toUpperCase()}: ${STATUS_TEXT[btn.dataset.set].toLowerCase()}${hasImpact && cur < 3 ? ". Переключитесь на следующий месяц, чтобы увидеть эффект." : ""}`);
    });
    $("#resetBtn").addEventListener("click", () => {
      decisionState = {};
      store.del(STATE_KEY);
      render();
      toast("Решения возвращены к базовому сценарию");
    });
    $("#logoutBtn").addEventListener("click", () => {
      store.del(AUTH_KEY, sessionStorage);
      location.reload();
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.target.closest("input")) return;
      if (ev.key === "ArrowRight") setEpoch(cur + 1);
      if (ev.key === "ArrowLeft") setEpoch(cur - 1);
    });
  }

  async function start() {
    $("#login").hidden = true;
    $("#app").hidden = false;
    try {
      EPOCHS = (await loadEpochs()).sort((a, b) => a.epoch - b.epoch);
    } catch {
      $("#hero").innerHTML = `<div class="empty" style="grid-column:1/-1">Не удалось загрузить данные из папки data/.</div>`;
      return;
    }
    try { decisionState = JSON.parse(store.get(STATE_KEY) || "{}") || {}; } catch { decisionState = {}; }
    const saved = Number(store.get(EPOCH_KEY));
    cur = Number.isInteger(saved) && saved >= 0 && saved < EPOCHS.length ? saved : 0;
    bind();
    render();
  }

  // ---------- Вход ----------
  if (store.get(AUTH_KEY, sessionStorage) === "1") {
    start();
  } else {
    $("#loginForm").addEventListener("submit", (ev) => {
      ev.preventDefault();
      const input = $("#pwd");
      if (sha256(normalizePass(input.value)) === PASS_HASH) {
        store.set(AUTH_KEY, "1", sessionStorage);
        start();
      } else {
        $("#loginErr").hidden = false;
        const card = $(".login__card");
        card.classList.remove("shake");
        void card.offsetWidth;
        card.classList.add("shake");
        input.select();
      }
    });
  }
})();
