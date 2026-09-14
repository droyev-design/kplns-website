/* יומן משפחה — client for the encrypted merged feed.
   Contract: docs/FEED_SPEC.md. Nothing here ever sends anything anywhere;
   the only network call is a GET of feed.json. */

'use strict';

const TZ       = 'Asia/Jerusalem';
const FEED_URL = 'feed.json';
const LS = { pass: 'cal.pass', payload: 'cal.payload', theme: 'cal.theme',
             off: 'cal.off', seq: 'cal.seq' };

// The envelope is served from a public static host, so everything outside the
// ciphertext is attacker-writable. Pin what we accept instead of obeying it:
// unbounded `iters` from a hostile file would hang the phone inside PBKDF2
// before authentication ever happens.
const KDF_LIMITS = { algo: 'PBKDF2-SHA256', minIters: 100000, maxIters: 600000, saltBytes: 16 };

const $ = (id) => document.getElementById(id);

let payload  = null;                       // last decrypted feed
let hidden   = new Set(readJSON(LS.off, []));   // source ids the user switched off
let view     = 'agenda';
let monthRef = null;                       // Date anchoring the month view
let selDay   = null;

/* ───────────────────────────── small helpers ───────────────────────────── */

function readJSON(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; }
  catch { return fallback; }
}
function writeJSON(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* private mode */ }
}
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

const fmtDate = (d, opts) => new Intl.DateTimeFormat('he-IL', { timeZone: TZ, ...opts }).format(d);

/** Calendar day of an event, as YYYY-MM-DD in Israel time. */
function dayKey(iso, allDay) {
  if (allDay) return iso.slice(0, 10);
  const p = new Intl.DateTimeFormat('en-CA', {
    timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(new Date(iso));
  return p;                                    // en-CA already gives YYYY-MM-DD
}
const todayKey = () => dayKey(new Date().toISOString(), false);

function addDays(key, n) {
  const d = new Date(key + 'T12:00:00Z');
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}
function keyToDate(key) { return new Date(key + 'T12:00:00Z'); }

function relTime(iso) {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 2)   return 'עכשיו';
  if (mins < 60)  return `לפני ${mins} דק׳`;
  const h = Math.round(mins / 60);
  if (h < 24)     return `לפני ${h} שע׳`;
  const d = Math.round(h / 24);
  return `לפני ${d} ימים`;
}

/* ──────────────────────────────── crypto ──────────────────────────────── */

const normalisePass = (s) => s.replace(/[\s-]/g, '').toLowerCase();

async function deriveKey(pass, salt, iters) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

function checkEnvelope(env) {
  const k = env?.kdf;
  if (env?.v !== 1 || env.cipher !== 'AES-256-GCM' || !k) throw new Error('badenvelope');
  if (k.algo !== KDF_LIMITS.algo || k.hash !== 'SHA-256') throw new Error('badenvelope');
  if (!(k.iters >= KDF_LIMITS.minIters && k.iters <= KDF_LIMITS.maxIters)) throw new Error('badenvelope');
  if (b64(k.salt).length !== KDF_LIMITS.saltBytes) throw new Error('badenvelope');
  if (b64(env.iv).length !== 12) throw new Error('badenvelope');
}

/** Throws 'badkey' (tag failed), 'badenvelope' (params) or 'replay' (older feed). */
async function decrypt(envelope, pass) {
  checkEnvelope(envelope);
  const key = await deriveKey(pass, b64(envelope.kdf.salt), envelope.kdf.iters);
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64(envelope.iv) }, key, b64(envelope.ct));
  } catch { throw new Error('badkey'); }
  const data = JSON.parse(new TextDecoder().decode(plain));

  // `seq` and `generated` come from inside the ciphertext, so they are the only
  // trustworthy freshness signals. The envelope's own `updated` is decoration:
  // anyone who can serve the file could pair last month's ciphertext with
  // today's timestamp, and we would show a month-old calendar with confidence.
  const seq = Number(data.seq);
  if (!Number.isFinite(seq)) throw new Error('badenvelope');
  const seen = Number(localStorage.getItem(LS.seq) || 0);
  if (seq < seen) throw new Error('replay');
  try { localStorage.setItem(LS.seq, String(seq)); } catch { /* private mode */ }

  return data;
}

/* ───────────────────────────────── data ───────────────────────────────── */

async function fetchFeed(pass) {
  const res = await fetch(`${FEED_URL}?t=${Date.now()}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`http ${res.status}`);
  return decrypt(await res.json(), pass);
}

/** Every calendar day an event touches. All-day `end` is EXCLUSIVE (iCal). */
function spanDays(ev) {
  const start = dayKey(ev.start, ev.allDay);
  if (!ev.allDay) return [start];
  let last = addDays(ev.end.slice(0, 10), -1);
  if (last < start) last = start;
  const out = [];
  for (let k = start; k <= last && out.length < 90; k = addDays(k, 1)) out.push(k);
  return out;
}

function visibleEvents() {
  return (payload?.events || []).filter((e) => !hidden.has(e.source));
}

function groupByDay(events) {
  const map = new Map();
  for (const ev of events) {
    for (const k of spanDays(ev)) {
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(ev);
    }
  }
  for (const [key, list] of map) {
    // Continuation strips of a multi-day event first (they are context, not
    // news), then all-day events starting today, then timed events in order.
    const rank = (e) => isContinuation(e, key) ? 0 : (e.allDay ? 1 : 2);
    list.sort((a, b) => rank(a) - rank(b) || a.start.localeCompare(b.start));
  }
  return map;
}

/** True when `key` is a later day of a multi-day all-day event. */
function isContinuation(ev, key) {
  return ev.allDay && ev.start.slice(0, 10) !== key;
}

/* ──────────────────────────────── render ─────────────────────────────── */

function dayHeading(key) {
  const t = todayKey();
  if (key === t)              return 'היום';
  if (key === addDays(t, 1))  return 'מחר';
  if (key === addDays(t, -1)) return 'אתמול';
  return fmtDate(keyToDate(key), { weekday: 'long' });
}

function eventNode(ev, key) {
  const el = document.createElement('div');

  // A 14-day vacation must not print 14 identical cards. Full card on the day
  // it starts; every later day gets a one-line strip.
  if (isContinuation(ev, key)) {
    el.className = 'ev-cont';
    const bar = document.createElement('span');
    bar.className = 'cont-bar';
    bar.style.background = ev.color;
    const days = spanDays(ev);
    const txt = document.createElement('span');
    txt.textContent = `${ev.title} · יום ${days.indexOf(key) + 1} מתוך ${days.length}`;
    el.append(bar, txt);
    return el;
  }

  el.className = `ev is-${ev.kind}`;

  const bar = document.createElement('div');
  bar.className = 'ev-bar';
  bar.style.background = ev.color;
  el.appendChild(bar);

  const body = document.createElement('div');
  body.className = 'ev-body';

  const time = document.createElement('div');
  time.className = 'ev-time';
  if (ev.allDay) {
    const days = spanDays(ev);
    if (days.length > 1) {
      const last = fmtDate(keyToDate(days[days.length - 1]), { day: 'numeric', month: 'numeric' });
      time.textContent = `כל היום · ${days.length} ימים, עד ${last}`;
    } else {
      time.textContent = 'כל היום';
    }
  } else {
    const s = fmtDate(new Date(ev.start), { hour: '2-digit', minute: '2-digit' });
    const e = fmtDate(new Date(ev.end),   { hour: '2-digit', minute: '2-digit' });
    // In an RTL paragraph "20:00–21:00" renders end-first. Isolate it as LTR.
    const bdi = document.createElement('bdi');
    bdi.dir = 'ltr';
    bdi.textContent = (e && e !== s) ? `${s}–${e}` : s;
    time.appendChild(bdi);
  }
  body.appendChild(time);

  const title = document.createElement('div');
  title.className = 'ev-title';
  title.textContent = ev.title;
  body.appendChild(title);

  const meta = [ev.location, ev.sourceLabel].filter(Boolean).join(' · ');
  if (meta) {
    const m = document.createElement('div');
    m.className = 'ev-meta';
    m.textContent = meta;
    body.appendChild(m);
  }

  el.appendChild(body);
  return el;
}

function renderAgenda() {
  const root = $('viewAgenda');
  root.textContent = '';
  const map = groupByDay(visibleEvents());
  const from = todayKey();
  const keys = [...map.keys()].filter((k) => k >= from).sort();

  // Always anchor on today, even when it is empty — otherwise the list opens on
  // some date next week with nothing saying "today is clear".
  if (keys[0] !== from) { keys.unshift(from); map.set(from, map.get(from) || []); }

  if (!keys.length) {
    const p = document.createElement('p');
    p.className = 'empty';
    p.textContent = 'אין אירועים קרובים ביומנים שנבחרו.';
    root.appendChild(p);
    return;
  }

  for (const key of keys) {
    const group = document.createElement('section');
    group.className = 'day-group';

    const head = document.createElement('div');
    head.className = 'day-head' + (key === from ? ' is-today' : '');
    const name = document.createElement('span');
    name.className = 'd-name';
    name.textContent = dayHeading(key);
    const date = document.createElement('span');
    date.className = 'd-date';
    date.textContent = fmtDate(keyToDate(key), { day: 'numeric', month: 'long' });
    head.append(name, date);
    group.appendChild(head);

    const evs = map.get(key);
    if (!evs.length) {
      const p = document.createElement('p');
      p.className = 'day-empty';
      p.textContent = 'אין אירועים.';
      group.appendChild(p);
    }
    for (const ev of evs) group.appendChild(eventNode(ev, key));
    root.appendChild(group);
  }
}

function renderMonth() {
  const map = groupByDay(visibleEvents());
  const ref = monthRef || new Date();
  const y = ref.getFullYear(), m = ref.getMonth();

  $('monthTitle').textContent = fmtDate(new Date(y, m, 1), { month: 'long', year: 'numeric' });

  const dow = $('dowRow');
  if (!dow.childElementCount) {
    // Israeli week starts on Sunday.
    for (const d of ['א', 'ב', 'ג', 'ד', 'ה', 'ו', 'ש']) {
      const c = document.createElement('div');
      c.textContent = d;
      dow.appendChild(c);
    }
  }

  const grid = $('monthGrid');
  grid.textContent = '';
  const first = new Date(y, m, 1);
  const lead  = first.getDay();                       // 0 = Sunday
  const days  = new Date(y, m + 1, 0).getDate();
  const t     = todayKey();

  for (let i = 0; i < lead; i++) {
    const blank = document.createElement('div');
    blank.className = 'cell is-blank';
    grid.appendChild(blank);
  }

  for (let d = 1; d <= days; d++) {
    const key = `${y}-${String(m + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    const evs = map.get(key) || [];

    const cell = document.createElement('button');
    cell.className = 'cell'
      + (key === t ? ' is-today' : '')
      + (key === selDay ? ' is-sel' : '')
      + (key < t ? ' is-off' : '');

    const n = document.createElement('span');
    n.className = 'n';
    n.textContent = String(d);
    cell.appendChild(n);

    const dots = document.createElement('span');
    dots.className = 'dots';
    for (const c of [...new Set(evs.map((e) => e.color))].slice(0, 4)) {
      const i = document.createElement('i');
      i.style.background = c;
      dots.appendChild(i);
    }
    cell.appendChild(dots);

    cell.addEventListener('click', () => { selDay = key; renderMonth(); });
    grid.appendChild(cell);
  }

  const panel = $('monthDay');
  panel.textContent = '';
  if (selDay) {
    const h = document.createElement('h3');
    h.textContent = `${dayHeading(selDay)} · ${fmtDate(keyToDate(selDay), { day: 'numeric', month: 'long' })}`;
    panel.appendChild(h);
    const evs = map.get(selDay) || [];
    if (!evs.length) {
      const p = document.createElement('p');
      p.className = 'empty';
      p.textContent = 'אין אירועים ביום הזה.';
      panel.appendChild(p);
    } else {
      for (const ev of evs) panel.appendChild(eventNode(ev, selDay));
    }
  }
}

function renderChips() {
  const box = $('chips');
  box.textContent = '';
  for (const s of payload?.sources || []) {
    const b = document.createElement('button');
    b.className = 'chip' + (hidden.has(s.id) ? ' is-off' : '');
    const dot = document.createElement('span');
    dot.className = 'dot';
    dot.style.background = s.color;
    b.append(dot, document.createTextNode(s.label));
    b.addEventListener('click', () => {
      hidden.has(s.id) ? hidden.delete(s.id) : hidden.add(s.id);
      writeJSON(LS.off, [...hidden]);
      renderChips(); renderCurrentView();
    });
    box.appendChild(b);
  }
}

function renderBanner() {
  const el = $('banner');
  const msgs = [];

  const ageH = (Date.now() - new Date(payload.generated).getTime()) / 3.6e6;
  if (ageH > 12) {
    msgs.push(`היומן לא התעדכן כבר ${Math.round(ageH)} שעות — ככל הנראה מחולל הפיד בשרת הביתי לא רץ.`);
  }
  const broken = (payload.status || []).filter((s) => s.ok === false);
  if (broken.length) {
    msgs.push(`לא נטענו: ${broken.map((s) => s.label).join(', ')} — ייתכן שחסרים אירועים.`);
  }

  el.textContent = msgs.join(' ');
  el.hidden = !msgs.length;
}

function renderCurrentView() {
  $('viewAgenda').hidden = view !== 'agenda';
  $('viewMonth').hidden  = view !== 'month';
  view === 'agenda' ? renderAgenda() : renderMonth();
}

function renderAll() {
  const now = new Date();
  $('todayDay').textContent  = fmtDate(now, { weekday: 'long' });
  $('todayDate').textContent = fmtDate(now, { day: 'numeric', month: 'long', year: 'numeric' });
  $('updated').textContent   = payload?.generated ? `עודכן ${relTime(payload.generated)}` : '';
  renderChips();
  renderBanner();
  renderCurrentView();
}

/* ──────────────────────────────── flow ───────────────────────────────── */

function showSetup(errorMsg) {
  $('app').hidden = true;
  $('setup').hidden = false;
  const err = $('setupError');
  err.hidden = !errorMsg;
  if (errorMsg) err.textContent = errorMsg;
  $('passSave').disabled = false;
  $('passInput').focus();
}

function showApp() {
  $('setup').hidden = true;
  $('app').hidden = false;
  renderAll();
}

async function refresh({ silent } = {}) {
  const pass = localStorage.getItem(LS.pass);
  if (!pass) return;
  const btn = $('refreshBtn');
  btn.classList.add('spin');
  try {
    payload = await fetchFeed(pass);
    writeJSON(LS.payload, payload);
    renderAll();
  } catch (e) {
    const el = $('banner');
    if (e.message === 'badkey') {
      localStorage.removeItem(LS.pass);
      showSetup('המפתח כבר לא מתאים לקובץ. ייתכן שהוחלף — הזן את החדש.');
    } else if (e.message === 'replay' || e.message === 'badenvelope') {
      // Refused on purpose: an older or malformed feed. Keep what we have and
      // say so loudly — a silent fallback here is exactly a missed appointment.
      el.textContent = e.message === 'replay'
        ? 'השרת החזיר גרסה ישנה יותר של היומן — נדחתה. מוצג המידע האחרון התקין.'
        : 'קובץ היומן לא תקין ונדחה. מוצג המידע האחרון התקין.';
      el.hidden = false;
    } else if (!silent) {
      el.textContent = payload
        ? 'אין חיבור — מוצג המידע השמור במכשיר.'
        : 'לא הצלחתי להוריד את היומן ואין עותק שמור.';
      el.hidden = false;
    }
  } finally {
    btn.classList.remove('spin');
  }
}

function applyTheme(mode) {
  // Stored bare (not JSON) — the pre-paint script in index.html reads it raw.
  try { localStorage.setItem(LS.theme, mode); } catch { /* private mode */ }
  const dark = mode === 'dark'
    || (mode === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
}

function wire() {
  $('passSave').addEventListener('click', async () => {
    const raw = normalisePass($('passInput').value);
    if (raw.length < 8) { showSetup('המפתח קצר מדי.'); return; }
    $('passSave').disabled = true;
    $('setupError').hidden = true;
    try {
      payload = await fetchFeed(raw);
      localStorage.setItem(LS.pass, raw);
      writeJSON(LS.payload, payload);
      showApp();
    } catch (e) {
      const msg = { badkey: 'מפתח שגוי. בדוק שהעתקת אותו במלואו.',
                    badenvelope: 'קובץ היומן בשרת לא תקין. נסה שוב מאוחר יותר.',
                    replay: 'השרת מחזיר גרסה ישנה של היומן. נסה שוב מאוחר יותר.' };
      showSetup(msg[e.message] || 'לא הצלחתי להוריד את היומן. בדוק חיבור לאינטרנט ונסה שוב.');
    }
  });
  $('passInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('passSave').click();
  });

  $('refreshBtn').addEventListener('click', () => refresh({}));

  $('themeBtn').addEventListener('click', () => {
    const order = ['system', 'light', 'dark'];
    const cur = localStorage.getItem(LS.theme) || 'system';
    applyTheme(order[(order.indexOf(cur) + 1) % order.length]);
  });

  $('forgetBtn').addEventListener('click', () => {
    localStorage.removeItem(LS.pass);
    localStorage.removeItem(LS.payload);
    payload = null;
    showSetup('');
  });

  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((t) => t.classList.remove('is-active'));
      tab.classList.add('is-active');
      view = tab.dataset.view;
      if (view === 'month' && !selDay) selDay = todayKey();
      renderCurrentView();
    });
  }
  $('monthPrev').addEventListener('click', () => {
    const r = monthRef || new Date();
    monthRef = new Date(r.getFullYear(), r.getMonth() - 1, 1); renderMonth();
  });
  $('monthNext').addEventListener('click', () => {
    const r = monthRef || new Date();
    monthRef = new Date(r.getFullYear(), r.getMonth() + 1, 1); renderMonth();
  });

  // Coming back to the app after a while should not show stale data.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && localStorage.getItem(LS.pass)) refresh({ silent: true });
  });
}

function boot() {
  wire();
  if (!localStorage.getItem(LS.pass)) { showSetup(''); return; }
  payload = readJSON(LS.payload, null);
  if (payload) showApp(); else $('app').hidden = false;
  refresh({ silent: !!payload });
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
}

boot();
