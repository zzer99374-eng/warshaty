"use strict";

/* =========================================================
   لوحة مدير المنصة — نسخة مُصلّبة ضد XSS و CSV injection.
   - كل محتوى يأتي من المستخدم يمر عبر esc() قبل أي innerHTML.
   - كل خلية CSV تُفحص قبل التصدير.
   - شاشة دخول مدمجة ترفض أي حساب ليس مدير منصة.
   ========================================================= */

const CFG = window.WARSHATY_CONFIG || {};
if (!CFG.SUPABASE_URL || !CFG.SUPABASE_ANON_KEY) {
  document.body.innerHTML = '<div class="card" style="margin:40px auto;max-width:480px">تعذر قراءة إعدادات Supabase من config.js</div>';
  throw new Error("missing config");
}

// جلسة منفصلة عن تطبيق الورش (نفس الدومين)، حتى لا يخرّج أحدهما الآخر من حسابه
const ADMIN_STORAGE_KEY = "warshaty-platform-admin-auth";
const sb = window.supabase.createClient(CFG.SUPABASE_URL, CFG.SUPABASE_ANON_KEY, {
  auth: { storageKey: ADMIN_STORAGE_KEY }
});

/** تسجيل خروج مضمون: لو طلب السيرفر وقف أو فشل، نمسح الجلسة المحلية بعد 3 ثواني. */
async function adminSignOut() {
  try { await Promise.race([sb.auth.signOut({ scope: "local" }), new Promise(r => setTimeout(r, 3000))]); } catch {}
  try { Object.keys(localStorage).filter(k => k.startsWith(ADMIN_STORAGE_KEY)).forEach(k => localStorage.removeItem(k)); } catch {}
}

/* ---------- أدوات ---------- */
const $ = s => document.querySelector(s);

/** تهريب HTML كامل. أي نص يأتي من مستخدم يجب أن يمر من هنا قبل innerHTML. */
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  }[c]));
}

/** تأمين خلية CSV: أي خلية تبدأ بـ = + - @ \t \r تُسبق بعلامة اقتباس أحادية. */
function csvSafe(v) {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

const STATUS_LABEL = { active:"نشطة", pending:"بانتظار التفعيل", suspended:"موقوفة", expired:"منتهية" };
const STATUS_CLASS = { active:"s-active", pending:"s-pending", suspended:"s-suspended", expired:"s-expired" };

const dt = v => {
  if (!v) return "—";
  try {
    const d = new Date(v);
    if (isNaN(d)) return String(v);
    const opts = { year:"numeric", month:"2-digit", day:"2-digit" };
    if (/^\d{4}-\d{2}-\d{2}$/.test(String(v))) opts.timeZone = "UTC"; // تاريخ بدون وقت: لا ننزاح يوم
    return d.toLocaleDateString("ar-EG", opts);
  }
  catch { return String(v); }
};
const dtTime = v => {
  if (!v) return "—";
  try {
    const d = new Date(v);
    if (isNaN(d)) return String(v);
    return d.toLocaleString("ar-EG", { year:"numeric", month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit" });
  }
  catch { return String(v); }
};
const dateInput = v => (v ? String(v).slice(0, 10) : "");

/** يرجع التسمية العربية إن وُجدت، وإلا النص كما هو. تُهرّب دائمًا. */
function statusLabel(key) {
  return esc(STATUS_LABEL[key] || key || "—");
}

let rows = [];
let listSeq = 0;

function toast(msg, kind = "") {
  const t = $("#toast");
  if (!t) return;
  t.textContent = msg;
  t.className = "toast" + (kind ? " " + kind : "");
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 2600);
}

/* ---------- شاشة الدخول ---------- */
function showLogin(message = "") {
  document.body.classList.add("is-logged-out");
  const old = document.getElementById("loginScreen");
  if (old) old.remove();

  const wrap = document.createElement("div");
  wrap.id = "loginScreen";
  wrap.className = "login-wrap";
  wrap.innerHTML = `
    <form class="login-card" id="loginForm" autocomplete="on">
      <h2 style="margin:0;font-family:var(--font-display);font-size:24px;color:var(--accent)">
        ورشتي <small style="display:block;font-family:var(--font-body);font-size:12px;font-weight:400;color:var(--muted)">لوحة مدير المنصة</small>
      </h2>
      ${message ? `<div class="note err">${esc(message)}</div>` : ""}
      <div class="f">
        <label for="li-email">البريد الإلكتروني</label>
        <input id="li-email" name="email" type="email" required autocomplete="email">
      </div>
      <div class="f">
        <label for="li-pass">كلمة المرور</label>
        <input id="li-pass" name="password" type="password" required minlength="6" autocomplete="current-password">
      </div>
      <button class="btn pri block" type="submit">دخول</button>
      <div class="note info" id="loginNote" hidden></div>
      <div class="muted" style="text-align:center">هذه الصفحة لمدراء المنصة فقط.</div>
    </form>`;
  document.body.appendChild(wrap);

  const form = wrap.querySelector("#loginForm");
  const note = wrap.querySelector("#loginNote");
  const btn  = form.querySelector("button[type=submit]");
  const first = form.querySelector("input");
  if (first) first.focus();

  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const email = String(fd.get("email") || "").trim();
    const password = String(fd.get("password") || "");
    btn.disabled = true;
    note.hidden = false;
    note.className = "note info";
    note.textContent = "جارٍ التحقق…";
    try {
      const { error: signErr } = await sb.auth.signInWithPassword({ email, password });
      if (signErr) throw signErr;

      const { data: isAdmin, error: rpcErr } = await sb.rpc("is_platform_admin");
      if (rpcErr) throw rpcErr;
      if (isAdmin !== true) {
        await adminSignOut();
        throw new Error("هذا الحساب ليس مدير منصة.");
      }
      // نجح — أعد التحميل ليهيّئ الجلسة من جديد
      location.reload();
    } catch (err) {
      note.className = "note err";
      note.textContent = err.message || "تعذر تسجيل الدخول";
      btn.disabled = false;
    }
  };
}

/* ---------- تبويبات ---------- */
function switchTab(name) {
  document.querySelectorAll(".tab").forEach(b => {
    const on = b.dataset.tab === name;
    b.setAttribute("aria-current", String(on));
    b.setAttribute("aria-selected", String(on));
  });
  const w = $("#tab-workshops"), a = $("#tab-audit");
  if (w) w.hidden = name !== "workshops";
  if (a) a.hidden = name !== "audit";
  if (name === "audit") loadAudit();
}
document.querySelectorAll(".tab").forEach(b => {
  b.onclick = () => switchTab(b.dataset.tab);
});

/* ---------- الورش ---------- */
async function loadStats() {
  const el = $("#stats"); if (!el) return;
  const { data, error } = await sb.rpc("admin_stats");
  if (error) { toast("تعذر تحميل الإحصائيات: " + error.message, "err"); return; }
  const cards = [
    ["إجمالي الورش",    Number(data?.total)     || 0],
    ["نشطة",            Number(data?.active)    || 0],
    ["بانتظار التفعيل", Number(data?.pending)   || 0],
    ["موقوفة",          Number(data?.suspended) || 0],
    ["منتهية",          Number(data?.expired)   || 0]
  ];
  el.innerHTML = cards.map(([l, v]) =>
    `<div class="stat"><span>${esc(l)}</span><b>${esc(v)}</b></div>`
  ).join("");
}

async function loadList(search = "") {
  const tbody = $("#rows"); if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:24px">جار التحميل…</td></tr>`;
  const mySeq = ++listSeq;
  const { data, error } = await sb.rpc("admin_list_workshops", { p_search: search || null });
  if (mySeq !== listSeq) return; // وصل رد أحدث، تجاهل هذا
  if (error) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:24px">تعذر التحميل: ${esc(error.message)}</td></tr>`;
    return;
  }
  rows = Array.isArray(data) ? data : [];
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:24px">لا نتائج.</td></tr>`;
    return;
  }
  const html = rows.map(r => {
    const s = r.workshop_status || "pending";
    const cls = STATUS_CLASS[s] || "s-pending";
    return `<tr data-id="${esc(r.workshop_id)}">
      <td class="mono">${esc(r.workshop_id)}</td>
      <td>${esc(r.workshop_name || "—")}</td>
      <td>${esc(r.owner_name || "—")}<div class="muted">${esc(r.owner_email || "")}</div></td>
      <td><span class="pill ${cls}">${statusLabel(s)}</span></td>
      <td>${esc(dt(r.sub_start))}</td>
      <td>${esc(dt(r.sub_end))}</td>
      <td>${esc(dt(r.created_at))}</td>
      <td><button class="btn sm" data-open="${esc(r.workshop_id)}">تفاصيل</button></td>
    </tr>`;
  }).join("");
  tbody.innerHTML = html;
}

/* ---------- تفاصيل ---------- */
function findRow(id) { return rows.find(x => x.workshop_id === id); }

function openDetails(id) {
  const r = findRow(id);
  if (!r) return;
  const s = r.workshop_status || "pending";

  // كل قيمة تُهرّب قبل وضعها في innerHTML
  const body = `
    <h2>${esc(r.workshop_name || "ورشة")}</h2>
    <dl class="details">
      <dt>المعرّف</dt><dd class="mono">${esc(r.workshop_id)}</dd>
      <dt>المالك</dt><dd>${esc(r.owner_name || "—")} <span class="muted">${esc(r.owner_email || "")}</span></dd>
      <dt>تاريخ التسجيل</dt><dd>${esc(dt(r.created_at))}</dd>
      <dt>الحالة الحالية</dt><dd><span class="pill ${STATUS_CLASS[s] || "s-pending"}">${statusLabel(s)}</span></dd>
    </dl>

    <div class="f">
      <label for="f-status">الحالة</label>
      <select id="f-status">
        <option value="active"    ${s === "active"    ? "selected" : ""}>نشطة</option>
        <option value="pending"   ${s === "pending"   ? "selected" : ""}>بانتظار التفعيل</option>
        <option value="suspended" ${s === "suspended" ? "selected" : ""}>موقوفة</option>
        <option value="expired"   ${s === "expired"   ? "selected" : ""}>منتهية</option>
      </select>
    </div>

    <div class="grid2">
      <div class="f"><label for="f-start">بداية الاشتراك</label>
        <input id="f-start" type="date" value="${esc(dateInput(r.sub_start))}"></div>
      <div class="f"><label for="f-end">نهاية الاشتراك</label>
        <input id="f-end" type="date" value="${esc(dateInput(r.sub_end))}"></div>
    </div>

    <div class="f"><label for="f-reason">سبب الإيقاف (يظهر لصاحب الورشة)</label>
      <input id="f-reason" value="${esc(r.suspended_reason || "")}">
    </div>
    <div class="f"><label for="f-notes">ملاحظات داخلية (لا تظهر لصاحب الورشة)</label>
      <textarea id="f-notes">${esc(r.admin_notes || "")}</textarea>
    </div>

    <div class="row" style="flex-wrap:wrap">
      <button class="btn pri grow" id="save">حفظ التعديلات</button>
      <button class="btn" id="close">إلغاء</button>
    </div>
    <div class="row" style="flex-wrap:wrap;gap:6px">
      <button class="btn good sm" data-quick="active">تفعيل سريع</button>
      <button class="btn warn sm" data-quick="suspended">إيقاف سريع</button>
      <button class="btn sm"      data-quick="pending">إرجاع للانتظار</button>
    </div>`;

  const layer = $("#layer");
  layer.innerHTML = `<div class="veil" id="veil"><div class="sheet" role="dialog" aria-modal="true">${body}</div></div>`;

  const onEsc = (e) => { if (e.key === "Escape") close(); };
  const close = () => { document.removeEventListener("keydown", onEsc); layer.innerHTML = ""; };
  document.addEventListener("keydown", onEsc);
  $("#close").onclick = close;
  $("#veil").addEventListener("click", e => { if (e.target.id === "veil") close(); });

  const collect = () => ({
    status: $("#f-status").value,
    start:  $("#f-start").value || null,
    end:    $("#f-end").value || null,
    reason: $("#f-reason").value.trim(),
    notes:  $("#f-notes").value.trim()
  });

  const submit = () => {
    const p = collect();
    if (p.status === "suspended") {
      if (!p.reason) { toast("اكتب سبب الإيقاف الأول", "err"); $("#f-reason").focus(); return; }
      if (s !== "suspended" && !confirm("تأكيد إيقاف هذه الورشة؟ صاحبها هيشوف السبب.")) return;
    }
    save(id, p, close);
  };
  $("#save").onclick = submit;
  layer.querySelectorAll("[data-quick]").forEach(b => {
    b.onclick = () => { $("#f-status").value = b.dataset.quick; submit(); };
  });
}

async function save(id, payload, close) {
  const btn = $("#save"); if (btn) btn.disabled = true;
  const { error } = await sb.rpc("admin_update_workshop", {
    p_workshop_id: id,
    p_status:  payload.status,
    p_start:   payload.start,
    p_end:     payload.end,
    p_reason:  payload.reason,
    p_notes:   payload.notes
  });
  if (btn) btn.disabled = false;
  if (error) { toast("فشل الحفظ: " + error.message, "err"); return; }
  toast("تم الحفظ", "ok");
  close();
  await Promise.all([ loadStats(), loadList($("#q").value.trim()) ]);
}

/* ---------- CSV ---------- */
function exportCsv() {
  if (!rows.length) { toast("لا بيانات للتصدير"); return; }
  const head = ["المعرّف","الورشة","المالك","البريد","الحالة","بداية الاشتراك","نهاية الاشتراك","تاريخ التسجيل"];
  const lines = [head.map(h => csvSafe(h)).join(",")];
  rows.forEach(r => {
    lines.push([
      r.workshop_id,
      r.workshop_name || "",
      r.owner_name || "",
      r.owner_email || "",
      STATUS_LABEL[r.workshop_status] || r.workshop_status || "",
      dateInput(r.sub_start),
      dateInput(r.sub_end),
      dateInput(r.created_at)
    ].map(csvSafe).join(","));
  });
  const csv = "\uFEFF" + lines.join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "workshops-" + new Date().toISOString().slice(0, 10) + ".csv";
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------- سجل العمليات ---------- */
async function loadAudit() {
  const tbody = $("#auditRows"); if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="4" class="muted" style="text-align:center;padding:24px">جار التحميل…</td></tr>`;
  const { data, error } = await sb.rpc("admin_list_audit", { p_limit: 200, p_workshop_id: null });
  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted" style="text-align:center;padding:24px">تعذر التحميل: ${esc(error.message)}</td></tr>`;
    return;
  }
  const list = Array.isArray(data) ? data : [];
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted" style="text-align:center;padding:24px">مفيش عمليات مسجلة لسه.</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(a => `
    <tr>
      <td class="mono">${esc(dtTime(a.created_at))}</td>
      <td>${esc(a.actor_email || "—")}</td>
      <td>${esc(a.workshop_name || a.workshop_id || "—")}</td>
      <td>${diffSummary(a.before, a.after)}</td>
    </tr>
  `).join("");
}

/** يرجع HTML مهرّبًا بالكامل. لا يُدرج أي نص خام. */
function diffSummary(b, a) {
  if (!b || !a) return "—";
  const parts = [];
  if (String(b.status || "") !== String(a.status || "")) {
    parts.push("الحالة: " + statusLabel(b.status) + " ← " + statusLabel(a.status));
  }
  if (String(b.subscription_start || "") !== String(a.subscription_start || "")) {
    parts.push("بداية الاشتراك: " + esc(b.subscription_start || "—") + " ← " + esc(a.subscription_start || "—"));
  }
  if (String(b.subscription_end || "") !== String(a.subscription_end || "")) {
    parts.push("نهاية الاشتراك: " + esc(b.subscription_end || "—") + " ← " + esc(a.subscription_end || "—"));
  }
  if (String(b.suspended_reason || "") !== String(a.suspended_reason || "")) {
    parts.push("سبب الإيقاف تغيّر");
  }
  if (String(b.admin_notes || "") !== String(a.admin_notes || "")) {
    parts.push("الملاحظات الداخلية تغيّرت");
  }
  return parts.length ? parts.join(" · ") : "لا تغيير ظاهر";
}

/* ---------- أحداث ---------- */
function bindEvents() {
  const q = $("#q");
  if (q) q.addEventListener("input", () => {
    clearTimeout(q._t);
    q._t = setTimeout(() => loadList(q.value.trim()), 300);
  });
  const rl = $("#btnReload");
  if (rl) rl.onclick = () => { loadStats(); loadList(q ? q.value.trim() : ""); };
  const ra = $("#btnReloadAudit");
  if (ra) ra.onclick = () => loadAudit();
  const ex = $("#btnExport");
  if (ex) ex.onclick = exportCsv;
  const lo = $("#btnLogout");
  if (lo) lo.onclick = async () => { await adminSignOut(); location.reload(); };
  const tb = $("#rows");
  if (tb) tb.addEventListener("click", e => {
    const b = e.target.closest("[data-open]");
    if (b) openDetails(b.dataset.open);
  });
}

/* ---------- تشغيل ---------- */
(async function init() {
  bindEvents();

  const { data: { session } } = await sb.auth.getSession();
  if (!session) { showLogin(); return; }

  const { data: isAdmin, error } = await sb.rpc("is_platform_admin");
  if (error || isAdmin !== true) {
    await adminSignOut();
    showLogin("هذا الحساب ليس مدير منصة.");
    return;
  }

  // مسموح
  document.body.classList.remove("is-logged-out");
  const ls = document.getElementById("loginScreen");
  if (ls) ls.remove();

  const who = $("#who");
  if (who) who.textContent = session.user?.email || "";

  await Promise.all([ loadStats(), loadList() ]);
})();