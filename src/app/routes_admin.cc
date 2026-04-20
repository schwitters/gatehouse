#include "app/routes.h"

#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

#include "app/http_utils.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/sha256.h"
#include "core/time.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/invite_repo.h"

namespace gatehouse::app {

namespace {

const char* kAdminInvitesPage = R"ADMIN(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%TITLE% – Invitations</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:980px}
    label{display:block;margin-top:14px}
    input{width:100%;padding:10px;margin-top:6px}
    button{margin-top:12px;padding:10px 14px}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .card{padding:16px;border:1px solid #ddd;border-radius:12px;margin-top:18px}
    code{background:#f4f4f4;padding:2px 6px;border-radius:6px}
    pre{background:#0b1020;color:#e6e6e6;padding:12px;border-radius:12px;overflow:auto}
    .ok{color:#0a7a2f}
    .err{color:#b00020}
    a{color:#0b57d0}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border-bottom:1px solid #eee;text-align:left;font-size:14px}
    th{font-weight:600}
    .pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#f4f4f4}
  </style>
</head>
<body>
  <h1>Invitations</h1>
  <p><a href="%B%/portal">Back to portal</a></p>

  <div class="card">
    <h2>Create invite</h2>
    <div class="row">
      <div>
        <label>Tenant OU (e.g. <code>k8s-20260118</code>)
          <input id="tenant_ou" placeholder="k8s-20260118" autocomplete="off">
        </label>
      </div>
      <div>
        <label>User UID (e.g. <code>krm</code>)
          <input id="uid" placeholder="krm" autocomplete="off">
        </label>
      </div>
    </div>
    <button id="btnCreate">Create invite</button>
    <p id="statusCreate"></p>
    <div id="outCreate"></div>
  </div>

  <div class="card">
    <h2>Uninvited LDAP Users</h2>
    <div class="row">
      <div>
        <label>Target Tenant OU
          <input id="uninvTenant" placeholder="k8s-20260118">
        </label>
      </div>
    </div>
    <button id="btnSearchUninvited">Find Users</button>
    <p id="statusUninvited"></p>
    <div id="uninvitedList"></div>
  </div>

  <div class="card">
    <h2>Latest invites</h2>
    <div class="row">
      <div>
        <label>Filter tenant_ou
          <input id="fltTenant" placeholder="(optional)">
        </label>
      </div>
      <div>
        <label>Filter uid
          <input id="fltUid" placeholder="(optional)">
        </label>
      </div>
    </div>
    <button id="btnRefresh">Refresh list</button>
    <p id="statusList"></p>
    <div id="list"></div>
  </div>

<script>
const _B='%B%';
function getCsrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)gh_csrf=([^;]+)/);
  return m ? m[1] : '';
}

async function apiJson(method, path, body) {
  const opt = {method, headers: {"Content-Type":"application/json", "X-CSRF-Token": getCsrfToken()}};
  if (body !== undefined) opt.body = JSON.stringify(body);
  const r = await fetch(_B+path, opt);
  const t = await r.text();
  let j = null;
  try { j = JSON.parse(t); } catch(e) {}
  return {ok: r.ok, status: r.status, json: j, text: t};
}

function setStatus(id, kind, msg) {
  const el = document.getElementById(id);
  el.className = kind;
  el.textContent = msg;
}

function renderJson(where, obj) {
  const out = document.getElementById(where);
  out.innerHTML = "";
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(obj, null, 2);
  out.appendChild(pre);
  if (obj && obj.invite_url) {
    const p = document.createElement("p");
    const a = document.createElement("a");
    a.href = obj.invite_url;
    a.textContent = "Open invite link";
    a.target = "_blank";
    p.appendChild(a);
    out.appendChild(p);
  }
}

function renderList(items) {
  const root = document.getElementById("list");
  root.innerHTML = "";
  if (!items || items.length === 0) {
    root.textContent = "No invites.";
    return;
  }
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = "<tr><th>created / dates</th><th>tenant</th><th>uid</th><th>email</th><th>status</th><th>actions</th></tr>";
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const it of items) {
    const tr = document.createElement("tr");

    const created = new Date(it.created_at * 1000).toLocaleString();
    const expires = new Date(it.expires_at * 1000).toLocaleString();
    let datesHtml = "<div>" + created + "</div><div style='color:#555;font-size:0.85em;margin-top:4px'>Expires: " + expires + "</div>";

    if (it.consumed_at && it.consumed_at > 0) {
        datesHtml += "<div style='color:#0a7a2f;font-size:0.85em'>Completed: " + new Date(it.consumed_at * 1000).toLocaleString() + "</div>";
    }
    if (it.revoked_at && it.revoked_at > 0) {
        datesHtml += "<div style='color:#b00020;font-size:0.85em'>Revoked: " + new Date(it.revoked_at * 1000).toLocaleString() + "</div>";
    }

    let pillColor = "#f4f4f4";
    let textColor = "#000";
    if (it.status_name === "Completed") { pillColor = "#e6f4ea"; textColor = "#137333"; }
    else if (it.status_name === "Revoked" || it.status_name === "Expired") { pillColor = "#fce8e6"; textColor = "#c5221f"; }
    else if (it.status_name === "StepupVerified") { pillColor = "#e8f0fe"; textColor = "#1a73e8"; }

    tr.innerHTML =
      "<td>" + datesHtml + "</td>" +
      "<td><code>" + it.tenant_id + "</code></td>" +
      "<td><code>" + (it.invited_uid||"") + "</code></td>" +
      "<td>" + it.invited_email + "</td>" +
      "<td><span class='pill' style='background:" + pillColor + ";color:" + textColor + ";font-weight:500'>" + it.status_name + "</span></td>" +
      "<td></td>";
    const td = tr.querySelectorAll("td")[5];

    const canRevoke = it.status !== 4 && it.status !== 5 && it.status !== 6;

    if (canRevoke) {
      const btnRevoke = document.createElement("button");
      btnRevoke.textContent = "Revoke";
      btnRevoke.style.marginRight = "8px";
      btnRevoke.onclick = async () => {
        if (!confirm("Are you sure you want to revoke this invitation for " + it.invited_email + "?")) return;
        const r = await apiJson("POST", "/api/admin/invites/revoke", {invite_id: it.invite_id});
        if (!r.ok) { alert("Revoke failed: " + (r.json && r.json.error ? r.json.error : r.text)); return; }
        await refresh();
      };
      td.appendChild(btnRevoke);
    } else if (it.invited_uid && it.tenant_id) {
      checkAndAddResetBtn(td, it.tenant_id, it.invited_uid);
    }

    const btnResend = document.createElement("button");
    btnResend.textContent = "Resend";
    btnResend.onclick = async () => {
      if (!confirm("Generate a new invite link for " + it.invited_email + "?")) return;
      const r = await apiJson("POST", "/api/admin/invites", {tenant_ou: it.tenant_id, uid: it.invited_uid});
      if (!r.ok) { alert("Resend failed: " + (r.json && r.json.error ? r.json.error : r.text)); return; }
      renderJson("outCreate", r.json || {});
      setStatus("statusCreate", "ok", "Resent as new invite.");
      await refresh();
    };
    td.appendChild(btnResend);

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  root.appendChild(table);
}

async function checkAndAddResetBtn(td, tenant_id, uid) {
  try {
    const r = await apiJson("GET", "/api/admin/user/krb-status?tenant_id=" + encodeURIComponent(tenant_id) + "&uid=" + encodeURIComponent(uid));
    if (!r.ok || !r.json || !r.json.has_krb_attrs) return;
    const btn = document.createElement("button");
    btn.textContent = "Reset Kerberos";
    btn.style.cssText = "margin-right:8px;background:#d93025;";
    btn.onclick = async () => {
      if (!confirm("Delete Kerberos attributes for " + uid + "?\n\nThis removes: krbPrincipalName, krbPrincipalKey, krbExtraData, krbLastPwdChange, krbLoginFailedCount")) return;
      const res = await apiJson("POST", "/api/admin/user/reset-krb", {tenant_id, uid});
      if (!res.ok) { alert("Reset failed: " + (res.json && res.json.error ? res.json.error : res.text)); return; }
      btn.remove();
    };
    td.insertBefore(btn, td.firstChild);
  } catch(e) {}
}

async function refresh() {
  setStatus("statusList", "", "Loading...");
  const t = document.getElementById("fltTenant").value.trim();
  const u = document.getElementById("fltUid").value.trim();
  const q = new URLSearchParams();
  if (t) q.set("tenant_id", t);
  if (u) q.set("invited_uid", u);
  const r = await fetch(_B+"/api/admin/invites/list?" + q.toString());
  const j = await r.json().catch(() => null);
  if (!r.ok) {
    setStatus("statusList", "err", "Error (" + r.status + ")");
    return;
  }
  setStatus("statusList", "ok", "Loaded " + (j.items ? j.items.length : 0) + " invite(s).");
  renderList(j.items || []);
}

async function searchUninvited() {
  setStatus("statusUninvited", "", "Searching LDAP...");
  const t = document.getElementById("uninvTenant").value.trim();
  if (!t) { setStatus("statusUninvited", "err", "Please enter a Tenant OU."); return; }

  const r = await fetch(_B+"/api/admin/uninvited?tenant_id=" + encodeURIComponent(t));
  const j = await r.json().catch(() => null);
  if (!r.ok) { setStatus("statusUninvited", "err", "Error: " + (j && j.error ? j.error : r.status)); return; }

  const items = j.items || [];
  setStatus("statusUninvited", "ok", "Found " + items.length + " uninvited user(s).");

  const root = document.getElementById("uninvitedList");
  root.innerHTML = "";
  if (items.length === 0) return;

  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>uid</th><th>email</th><th>actions</th></tr></thead>";
  const tbody = document.createElement("tbody");

  for (const it of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = "<td><code>" + it.uid + "</code></td><td>" + it.mail + "</td><td></td>";
    const td = tr.querySelectorAll("td")[2];

    const btn = document.createElement("button");
    btn.textContent = "Send Invite";
    btn.onclick = async () => {
      btn.disabled = true;
      btn.textContent = "Sending...";
      const res = await apiJson("POST", "/api/admin/invites", {tenant_ou: t, uid: it.uid});
      if (!res.ok) {
        alert("Failed: " + (res.json && res.json.error ? res.json.error : res.text));
        btn.disabled = false;
        btn.textContent = "Send Invite";
      } else {
        btn.textContent = "Sent!";
        await refresh();
      }
    };
    td.appendChild(btn);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  root.appendChild(table);
}
document.getElementById("btnSearchUninvited").addEventListener("click", searchUninvited);

document.getElementById("btnCreate").addEventListener("click", async () => {
  const tenant_ou = document.getElementById("tenant_ou").value.trim();
  const uid = document.getElementById("uid").value.trim();
  if (!tenant_ou || !uid) { setStatus("statusCreate","err","tenant_ou and uid are required"); return; }
  setStatus("statusCreate","", "Working...");
  const r = await apiJson("POST", "/api/admin/invites", {tenant_ou, uid});
  if (!r.ok) {
    setStatus("statusCreate","err","Error ("+r.status+"): " + (r.json && r.json.error ? r.json.error : r.text));
    if (r.json) renderJson("outCreate", r.json);
    return;
  }
  setStatus("statusCreate","ok","Invite created and email queued/sent.");
  renderJson("outCreate", r.json || {});
  await refresh();
});

document.getElementById("btnRefresh").addEventListener("click", refresh);
refresh();
</script>
</body>
</html>)ADMIN";

}  // namespace

void RegisterAdminRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  const std::string& B = ctx.cfg.base_uri;

  // ---- Admin invitations page ----
  app.route_dynamic(B + "/admin/invites").methods("GET"_method)([&ctx](const crow::request& req) {
    const std::string& B = ctx.cfg.base_uri;
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) return RedirectTo(B + "/login");
    if (!IsAdminUid(ctx, s->uid)) return HtmlPage(403, "<h1>Forbidden</h1>");
    // ApplyTitle also substitutes %B% with base_uri
    std::string page = ApplyTitle(kAdminInvitesPage, ctx.cfg.instance_title);
    std::size_t pos = 0;
    while ((pos = page.find("%B%", pos)) != std::string::npos) {
      page.replace(pos, 3, B);
      pos += B.size();
    }
    return HtmlPage(200, page);
  });

  // ---- Admin tenant/user overview page ----
  app.route_dynamic(B + "/admin/tenants").methods("GET"_method)([&ctx](const crow::request& req) {
    const std::string& B = ctx.cfg.base_uri;
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) return RedirectTo(B + "/login");
    if (!IsAdminUid(ctx, s->uid)) return HtmlPage(403, "<h1>Forbidden</h1>");

    const std::string csrf = s->csrf_secret_hex;
    std::string html = "<!doctype html><html><head><meta charset='utf-8'>"
                       "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                       "<title>" + ctx.cfg.instance_title + " \xe2\x80\x93 Tenant Overview</title>"
                       "<style>"
                       "body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:1100px;background:#f9f9f9;color:#222}"
                       ".card{background:#fff;padding:20px 24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.05);margin-bottom:20px}"
                       "h1,h2,h3{margin-top:0} a{color:#0b57d0;font-weight:600;text-decoration:none} a:hover{text-decoration:underline}"
                       "table{width:100%;border-collapse:collapse;margin-top:12px}"
                       "th,td{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;font-size:14px;vertical-align:top}"
                       "th{font-weight:600;background:#fafafa}"
                       "code{background:#f0f0f0;padding:2px 6px;border-radius:4px;font-size:0.88em}"
                       ".host-pill{display:inline-block;background:#e8f0fe;color:#1a73e8;padding:2px 8px;border-radius:999px;font-size:12px;margin:2px 2px 2px 0}"
                       ".err{color:#b00020} .muted{color:#777;font-size:13px}"
                       "select{padding:8px;border-radius:6px;border:1px solid #ccc;font-size:14px;margin-right:8px}"
                       "button{padding:9px 16px;border:none;border-radius:6px;background:#0b57d0;color:#fff;cursor:pointer;font-weight:600}"
                       "button:hover{background:#0842a0}"
                       "</style></head><body>"
                       "<h1>Tenant &amp; User Overview</h1>"
                       "<p><a href='" + B + "/portal'>&larr; Back to portal</a></p>"
                       "<div class='card'>"
                       "<h2>Select Tenant</h2>"
                       "<select id='tenantSel'><option value=''>Loading...</option></select>"
                       "<button id='btnLoad'>Load Users &amp; Hosts</button>"
                       "<p id='status' class='muted'></p>"
                       "</div>"
                       "<div id='result'></div>"
                       "<script>";

    html += "const _B='" + B + "';\n";
    html += "const CSRF = '" + csrf + "';\n";
    html += R"JS(
const STATUS_NAMES = {
  '-1': {label:'None',      bg:'#f0f0f0', fg:'#555'},
   '0': {label:'Invited',   bg:'#fff3cd', fg:'#856404'},
   '1': {label:'LinkVerified', bg:'#cfe2ff', fg:'#0a58ca'},
   '2': {label:'StepupSent',   bg:'#cfe2ff', fg:'#0a58ca'},
   '3': {label:'StepupVerified', bg:'#d1ecf1', fg:'#0c5460'},
   '4': {label:'Completed', bg:'#d1e7dd', fg:'#0f5132'},
   '5': {label:'Expired',   bg:'#f8d7da', fg:'#842029'},
   '6': {label:'Revoked',   bg:'#f8d7da', fg:'#842029'},
};

function statusPill(status, expiresAt) {
  const s = String(status);
  const info = STATUS_NAMES[s] || {label:'Unknown', bg:'#eee', fg:'#333'};
  let label = info.label;
  if ((status === 0 || status === 1 || status === 2 || status === 3) && expiresAt > 0 && expiresAt < Date.now()/1000) {
    label = 'Expired'; return '<span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:500;background:#f8d7da;color:#842029">' + label + '</span>';
  }
  return '<span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:500;background:' + info.bg + ';color:' + info.fg + '">' + label + '</span>';
}

async function loadTenants() {
  const r = await fetch(_B+'/api/admin/tenants');
  const j = await r.json().catch(() => null);
  const sel = document.getElementById('tenantSel');
  if (!r.ok || !j || !j.items) { sel.innerHTML = '<option>Error loading tenants</option>'; return; }
  sel.innerHTML = '<option value="">-- choose tenant --</option>';
  for (const t of j.items) {
    const o = document.createElement('option');
    o.value = t; o.textContent = t;
    sel.appendChild(o);
  }
}

async function sendInvite(tenantId, uid, btnEl) {
  btnEl.disabled = true;
  const orig = btnEl.textContent;
  btnEl.textContent = 'Sending...';
  const r = await fetch(_B+'/api/admin/invites', {
    method: 'POST',
    headers: {'Content-Type':'application/json','X-CSRF-Token': CSRF},
    body: JSON.stringify({tenant_ou: tenantId, uid})
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) {
    alert('Failed: ' + (j && j.error ? j.error : r.status));
    btnEl.disabled = false;
    btnEl.textContent = orig;
    return;
  }
  await loadUsers();
}

async function resetKrb(tenantId, uid, btnEl) {
  if (!confirm('Kerberos-Attribute für "' + uid + '" löschen?')) return;
  btnEl.disabled = true;
  const orig = btnEl.textContent;
  btnEl.textContent = '...';
  const r = await fetch(_B+'/api/admin/user/reset-krb', {
    method: 'POST',
    headers: {'Content-Type':'application/json','X-CSRF-Token': CSRF},
    body: JSON.stringify({tenant_id: tenantId, uid})
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) alert('Fehler: ' + (j && j.error ? j.error : r.status));
  btnEl.disabled = false;
  btnEl.textContent = orig;
}

async function resetInvite(tenantId, uid, btnEl) {
  if (!confirm('Alle Einladungen für "' + uid + '" zurücksetzen, E-Mail aktualisieren und neu einladen?')) return;
  btnEl.disabled = true;
  const orig = btnEl.textContent;
  btnEl.textContent = '...';
  const r = await fetch(_B+'/api/admin/user/reset-invite', {
    method: 'POST',
    headers: {'Content-Type':'application/json','X-CSRF-Token': CSRF},
    body: JSON.stringify({tenant_id: tenantId, uid})
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) {
    alert('Fehler: ' + (j && j.error ? j.error : r.status));
    btnEl.disabled = false;
    btnEl.textContent = orig;
    return;
  }
  await loadUsers();
}

async function loadUsers() {
  const t = document.getElementById('tenantSel').value;
  if (!t) { document.getElementById('status').textContent = 'Please select a tenant.'; return; }
  document.getElementById('status').textContent = 'Loading...';
  document.getElementById('result').innerHTML = '';
  const r = await fetch(_B+'/api/admin/tenant-users?tenant_id=' + encodeURIComponent(t),
                        {headers: {'X-CSRF-Token': CSRF}});
  const j = await r.json().catch(() => null);
  if (!r.ok || !j) {
    document.getElementById('status').textContent = 'Error: ' + (j && j.error ? j.error : r.status);
    return;
  }
  const users = j.users || [];
  document.getElementById('status').textContent = users.length + ' user(s) found.';

  if (users.length === 0) {
    document.getElementById('result').innerHTML = '<div class="card"><p>No users found in this tenant.</p></div>';
    return;
  }

  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML = '<h2>Users in <code>' + escHtml(t) + '</code></h2>';

  const table = document.createElement('table');
  table.innerHTML =
    '<thead><tr><th>UID</th><th>First Name</th><th>Last Name</th><th>Email</th>' +
    '<th>Invitation</th><th>Managed Hosts</th><th>Actions</th></tr></thead>';
  const tbody = document.createElement('tbody');

  for (const u of users) {
    const tr = document.createElement('tr');

    let hostsHtml = '';
    if (u.hosts && u.hosts.length > 0) {
      for (const h of u.hosts) {
        hostsHtml += '<span class="host-pill" title="' + escHtml(h.dn) + '">';
        hostsHtml += escHtml(h.hostname || h.dn);
        if (h.ip) hostsHtml += ' <code>' + escHtml(h.ip) + '</code>';
        hostsHtml += '</span>';
      }
    } else {
      hostsHtml = '<span class="muted">\xe2\x80\x94</span>';
    }

    const st = u.invite_status;
    let invHtml = statusPill(st, u.invite_expires_at);
    if (st >= 0 && u.invite_created_at > 0) {
      invHtml += '<br><span class="muted">' + new Date(u.invite_created_at * 1000).toLocaleDateString() + '</span>';
    }
    if (u.invite_expires_at > 0 && st !== 4) {
      const exp = new Date(u.invite_expires_at * 1000);
      invHtml += '<br><span class="muted" title="Expires">exp: ' + exp.toLocaleDateString() + '</span>';
    }

    tr.innerHTML =
      '<td><code>' + escHtml(u.uid) + '</code></td>' +
      '<td>' + escHtml(u.given_name) + '</td>' +
      '<td>' + escHtml(u.surname) + '</td>' +
      '<td>' + escHtml(u.mail) + '</td>' +
      '<td>' + invHtml + '</td>' +
      '<td>' + hostsHtml + '</td>' +
      '<td></td>';

    const td = tr.querySelectorAll('td')[6];
    td.style.cssText = 'white-space:nowrap';
    const isActive = st === 0 || st === 1 || st === 2 || st === 3;
    const isCompleted = st === 4;
    const btnStyle = 'padding:4px 8px;font-size:12px;border:none;border-radius:4px;cursor:pointer;margin:2px;';
    if (!isCompleted) {
      const btn = document.createElement('button');
      btn.textContent = isActive ? 'Resend' : 'Send Invite';
      btn.style.cssText = btnStyle;
      btn.onclick = () => sendInvite(t, u.uid, btn);
      td.appendChild(btn);
    }
    const krbBtn = document.createElement('button');
    krbBtn.textContent = 'Kerberos Reset';
    krbBtn.style.cssText = btnStyle + 'background:#fd7e14;color:#fff;';
    krbBtn.onclick = () => resetKrb(t, u.uid, krbBtn);
    td.appendChild(krbBtn);
    const riBtn = document.createElement('button');
    riBtn.textContent = 'Reset Invitation';
    riBtn.style.cssText = btnStyle + 'background:#0b57d0;color:#fff;';
    riBtn.onclick = () => resetInvite(t, u.uid, riBtn);
    td.appendChild(riBtn);

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  card.appendChild(table);
  document.getElementById('result').appendChild(card);
}

function escHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.getElementById('btnLoad').addEventListener('click', loadUsers);
loadTenants();
)JS";
    html += "</script></body></html>";
    return HtmlPage(200, html);
  });

  // ---- API: List uninvited users ----
  app.route_dynamic(B + "/api/admin/uninvited").methods("GET"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

    const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
    if (tenant.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id required"; return Json(400, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

    auto ldap_res = ctx.ldap_dir->ListUsers(tenant);
    if (!ldap_res.ok()) {
      std::fprintf(stderr, "[gatehouse][ldap] ListUsers failed for %s: %s\n",
                   tenant.c_str(), ldap_res.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
    }

    auto inv_res = ctx.invites.GetInvitedUids(tenant, core::UnixNow());
    if (!inv_res.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=inv_res.status().ToString(); return Json(500, v); }

    const std::vector<std::string> invited = inv_res.value();
    auto is_invited = [&](const std::string& u) {
      for (const auto& x : invited) if (x == u) return true;
      return false;
    };

    crow::json::wvalue v;
    v["ok"] = true;
    v["items"] = crow::json::wvalue::list();
    unsigned int idx = 0;
    for (const auto& u : ldap_res.value()) {
      if (!is_invited(u.uid)) {
        crow::json::wvalue it;
        it["uid"] = u.uid;
        it["mail"] = u.mail;
        v["items"][idx++] = std::move(it);
      }
    }
    return Json(200, v);
  });

  // ---- API: List latest invites (with optional filters) ----
  app.route_dynamic(B + "/api/admin/invites/list").methods("GET"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

    const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
    const std::string uid    = req.url_params.get("invited_uid") ? req.url_params.get("invited_uid") : "";

    auto rows = ctx.invites.ListLatest(50, tenant, uid);
    if (!rows.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=rows.status().ToString(); return Json(500, v); }

    crow::json::wvalue v;
    v["ok"] = true;
    v["items"] = crow::json::wvalue::list();
    unsigned int idx = 0;
    for (const auto& r : rows.value()) {
      crow::json::wvalue it;
      it["invite_id"]    = r.invite_id;
      it["tenant_id"]    = r.tenant_id;
      it["invited_uid"]  = r.invited_uid;
      it["invited_email"]= r.invited_email;
      it["status"]       = static_cast<int>(r.status);
      it["status_name"]  = InviteStatusName(r.status);
      it["created_at"]   = r.created_at;
      it["expires_at"]   = r.expires_at;
      it["revoked_at"]   = r.revoked_at;
      it["consumed_at"]  = r.consumed_at;
      it["created_by"]   = r.created_by;
      v["items"][idx++] = std::move(it);
    }
    return Json(200, v);
  });

  // ---- API: Revoke invite ----
  app.route_dynamic(B + "/api/admin/invites/revoke").methods("POST"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

    auto body = crow::json::load(req.body);
    if (!body || !body.has("invite_id")) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need invite_id)"; return Json(400, v); }
    const std::string invite_id = std::string(body["invite_id"].s());
    if (invite_id.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="invite_id empty"; return Json(400, v); }

    std::string inv_tenant_id, inv_uid;
    {
      auto inv = ctx.invites.GetById(invite_id);
      if (inv.ok() && inv.value().has_value()) {
        inv_tenant_id = inv.value()->tenant_id;
        inv_uid       = inv.value()->invited_uid;
      }
    }

    auto rc = ctx.invites.Revoke(invite_id, core::UnixNow());
    if (!rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=rc.status().ToString(); return Json(500, v); }

    if (ctx.ldap_dir.has_value() && !inv_tenant_id.empty() && !inv_uid.empty()) {
      auto del_rc = ctx.ldap_dir->DeleteKrbAttributes(inv_tenant_id, inv_uid);
      if (!del_rc.ok()) {
        std::fprintf(stderr, "[gatehouse][ldap] revoke: DeleteKrbAttributes failed for %s/%s: %s\n",
                     inv_tenant_id.c_str(), inv_uid.c_str(),
                     del_rc.status().ToString().c_str());
      }
    }

    crow::json::wvalue v; v["ok"]=true; return Json(200, v);
  });

  // ---- API: Create invite ----
  app.route_dynamic(B + "/api/admin/invites").methods("POST"_method)([&ctx](const crow::request& req) {
    try {
      auto s = RequireAuth(ctx, req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
      if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

      auto body = crow::json::load(req.body);
      if (!body || !body.has("tenant_ou") || !body.has("uid")) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_ou, uid)"; return Json(400, v);
      }
      const std::string tenant_ou = std::string(body["tenant_ou"].s());
      const std::string uid       = std::string(body["uid"].s());
      if (tenant_ou.empty() || uid.empty()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_ou/uid empty"; return Json(400, v);
      }

      // MED-04: Validate uid and tenant_ou against a strict allowlist to
      // prevent LDAP-DN-injection or malformed Kerberos principal names.
      auto is_safe_name = [](const std::string& name) -> bool {
        if (name.empty() || name.size() > 64) return false;
        for (char c : name) {
          if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '_' || c == '.')) {
            return false;
          }
        }
        return true;
      };
      if (!is_safe_name(uid)) {
        crow::json::wvalue v; v["ok"]=false;
        v["error"]="uid contains invalid characters (allowed: a-z 0-9 - _ .)";
        return Json(400, v);
      }
      if (!is_safe_name(tenant_ou)) {
        crow::json::wvalue v; v["ok"]=false;
        v["error"]="tenant_ou contains invalid characters (allowed: a-z 0-9 - _ .)";
        return Json(400, v);
      }

      std::optional<std::string> mail;
      if (ctx.ldap_dir.has_value()) {
        auto rc = ctx.ldap_dir->LookupMail(tenant_ou, uid);
        if (!rc.ok()) {
          std::fprintf(stderr, "[gatehouse][ldap] LookupMail failed for %s/%s: %s\n",
                       tenant_ou.c_str(), uid.c_str(), rc.status().ToString().c_str());
          crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
        }
        mail = rc.value();
      } else if (!ctx.cfg.ldif_path.empty()) {
        mail = ctx.ldif_dir.LookupMail(tenant_ou, uid);
      } else {
        crow::json::wvalue v; v["ok"]=false; v["error"]="no directory configured"; return Json(409, v);
      }

      if (!mail.has_value() || mail->empty()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="user not found or missing mail"; return Json(404, v);
      }

      // Revoke any existing pending invites before creating a new one.
      (void)ctx.invites.RevokePending(tenant_ou, uid, core::UnixNow());

      auto token_bytes    = core::RandomBytes(32);
      auto invite_id_bytes = core::RandomBytes(16);
      if (!token_bytes.ok() || !invite_id_bytes.ok()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
      }
      const std::string token_hex = core::HexEncode(token_bytes.value());

      auto token_hash = core::Sha256(token_bytes.value());
      if (!token_hash.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v); }

      infra::InviteRow row;
      row.invite_id    = core::HexEncode(invite_id_bytes.value());
      row.tenant_id    = tenant_ou;
      row.invited_email = *mail;
      row.invited_uid  = uid;
      row.token_hash   = std::move(token_hash.value());
      row.status       = infra::InviteStatus::kInvited;
      row.created_at   = core::UnixNow();
      row.expires_at   = row.created_at + ctx.cfg.invite_ttl_seconds;
      row.created_by   = s->uid;

      auto ins = ctx.invites.Insert(row);
      if (!ins.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=ins.status().ToString(); return Json(500, v); }

      const std::string invite_url = ctx.cfg.public_base_url + "/invite/accept?token=" + token_hex;
      const std::string subject    = "[" + ctx.cfg.instance_title + "] You have been invited to " + tenant_ou;
      const std::string body_txt   =
          "Hello,\n\n"
          "you have been invited to " + ctx.cfg.instance_title + ".\n\n"
          "Tenant: " + tenant_ou + "\n"
          "User: " + uid + "\n\n"
          "Accept invitation:\n" + invite_url + "\n\n";

      auto mail_rc = ctx.email.SendText(*mail, subject, body_txt);
      if (!mail_rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="mail send failed: " + mail_rc.status().ToString(); return Json(502, v); }

      crow::json::wvalue v;
      v["ok"]           = true;
      v["tenant_ou"]    = tenant_ou;
      v["uid"]          = uid;
      v["invited_email"]= *mail;
      v["invite_url"]   = invite_url;
      v["expires_at"]   = row.expires_at;
      return Json(200, v);
    } catch (const std::exception& e) {
      crow::json::wvalue v; v["ok"]=false; v["error"]=std::string("exception: ") + e.what(); return Json(500, v);
    } catch (...) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="unknown exception"; return Json(500, v);
    }
  });

  // ---- API: Kerberos attribute status for a user ----
  app.route_dynamic(B + "/api/admin/user/krb-status").methods("GET"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["has_krb_attrs"]=false; return Json(200, v); }

    const std::string tenant_id = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
    const std::string uid       = req.url_params.get("uid") ? req.url_params.get("uid") : "";
    if (tenant_id.empty() || uid.empty()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id and uid required"; return Json(400, v);
    }

    auto has = ctx.ldap_dir->HasKrbAttributes(tenant_id, uid);
    if (!has.ok()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]=has.status().ToString(); return Json(502, v);
    }

    crow::json::wvalue v;
    v["ok"] = true;
    v["has_krb_attrs"] = has.value();
    return Json(200, v);
  });

  // ---- API: Reset Kerberos attributes for a user ----
  app.route_dynamic(B + "/api/admin/user/reset-krb").methods("POST"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

    auto body = crow::json::load(req.body);
    if (!body || !body.has("tenant_id") || !body.has("uid")) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_id, uid)"; return Json(400, v);
    }
    const std::string tenant_id = std::string(body["tenant_id"].s());
    const std::string uid       = std::string(body["uid"].s());
    if (tenant_id.empty() || uid.empty()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id/uid empty"; return Json(400, v);
    }

    auto rc = ctx.ldap_dir->DeleteKrbAttributes(tenant_id, uid);
    if (!rc.ok()) {
      std::fprintf(stderr, "[gatehouse][ldap] reset-krb failed for %s/%s: %s\n",
                   tenant_id.c_str(), uid.c_str(), rc.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]=rc.status().ToString(); return Json(502, v);
    }

    crow::json::wvalue v; v["ok"]=true; return Json(200, v);
  });

  // ---- API: Reset invitation (revoke all + delete krb attrs + new invite) ----
  app.route_dynamic(B + "/api/admin/user/reset-invite").methods("POST"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

    auto body = crow::json::load(req.body);
    if (!body || !body.has("tenant_id") || !body.has("uid")) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_id, uid)"; return Json(400, v);
    }
    const std::string tenant_id = std::string(body["tenant_id"].s());
    const std::string uid       = std::string(body["uid"].s());
    if (tenant_id.empty() || uid.empty()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id/uid empty"; return Json(400, v);
    }
    auto safe_name = [](const std::string& n) -> bool {
      if (n.empty() || n.size() > 64) return false;
      for (char c : n) if (!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.')) return false;
      return true;
    };
    if (!safe_name(uid) || !safe_name(tenant_id)) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid characters in tenant_id or uid"; return Json(400, v);
    }

    const std::int64_t now = core::UnixNow();

    // 1. Revoke all invites (including completed).
    (void)ctx.invites.RevokeAll(tenant_id, uid, now);

    // 2. Delete Kerberos attributes so the principal can be recreated.
    if (ctx.ldap_dir.has_value()) {
      auto krc = ctx.ldap_dir->DeleteKrbAttributes(tenant_id, uid);
      if (!krc.ok()) {
        std::fprintf(stderr, "[gatehouse][reset-invite] DeleteKrbAttributes failed for %s/%s: %s\n",
                     tenant_id.c_str(), uid.c_str(), krc.status().ToString().c_str());
      }
    }

    // 3. Look up current email from LDAP.
    std::optional<std::string> mail;
    if (ctx.ldap_dir.has_value()) {
      auto rc = ctx.ldap_dir->LookupMail(tenant_id, uid);
      if (!rc.ok()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
      }
      mail = rc.value();
    } else if (!ctx.cfg.ldif_path.empty()) {
      mail = ctx.ldif_dir.LookupMail(tenant_id, uid);
    } else {
      crow::json::wvalue v; v["ok"]=false; v["error"]="no directory configured"; return Json(409, v);
    }
    if (!mail.has_value() || mail->empty()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="user not found or missing mail"; return Json(404, v);
    }

    // 4. Create new invite and send email.
    auto token_bytes     = core::RandomBytes(32);
    auto invite_id_bytes = core::RandomBytes(16);
    if (!token_bytes.ok() || !invite_id_bytes.ok()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
    }
    const std::string token_hex = core::HexEncode(token_bytes.value());
    auto token_hash = core::Sha256(token_bytes.value());
    if (!token_hash.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v); }

    infra::InviteRow row;
    row.invite_id     = core::HexEncode(invite_id_bytes.value());
    row.tenant_id     = tenant_id;
    row.invited_email = *mail;
    row.invited_uid   = uid;
    row.token_hash    = std::move(token_hash.value());
    row.status        = infra::InviteStatus::kInvited;
    row.created_at    = now;
    row.expires_at    = now + ctx.cfg.invite_ttl_seconds;
    row.created_by    = s->uid;

    auto ins = ctx.invites.Insert(row);
    if (!ins.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=ins.status().ToString(); return Json(500, v); }

    const std::string invite_url = ctx.cfg.public_base_url + "/invite/accept?token=" + token_hex;
    const std::string subject    = "[" + ctx.cfg.instance_title + "] You have been invited to " + tenant_id;
    const std::string body_txt   =
        "Hello,\n\nyou have been invited to " + ctx.cfg.instance_title + ".\n\n"
        "Tenant: " + tenant_id + "\nUser: " + uid + "\n\n"
        "Accept invitation:\n" + invite_url + "\n\n";

    auto mail_rc = ctx.email.SendText(*mail, subject, body_txt);
    if (!mail_rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="mail send failed: " + mail_rc.status().ToString(); return Json(502, v); }

    crow::json::wvalue v;
    v["ok"]            = true;
    v["tenant_id"]     = tenant_id;
    v["uid"]           = uid;
    v["invited_email"] = *mail;
    v["expires_at"]    = row.expires_at;
    return Json(200, v);
  });

  // ---- API: List tenants ----
  app.route_dynamic(B + "/api/admin/tenants").methods("GET"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

    auto res = ctx.ldap_dir->ListTenants();
    if (!res.ok()) {
      std::fprintf(stderr, "[gatehouse][ldap] ListTenants failed: %s\n",
                   res.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
    }

    crow::json::wvalue v;
    v["ok"] = true;
    v["items"] = crow::json::wvalue::list();
    unsigned int idx = 0;
    for (const auto& t : res.value()) {
      v["items"][idx++] = t;
    }
    return Json(200, v);
  });

  // ---- API: List users with hosts for a tenant ----
  app.route_dynamic(B + "/api/admin/tenant-users").methods("GET"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

    const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
    if (tenant.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id required"; return Json(400, v); }

    auto res = ctx.ldap_dir->ListUsersWithHosts(tenant);
    if (!res.ok()) {
      std::fprintf(stderr, "[gatehouse][ldap] ListUsersWithHosts failed for %s: %s\n",
                   tenant.c_str(), res.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
    }

    // Build uid -> latest invite map.
    auto inv_res = ctx.invites.GetLatestPerUid(tenant);
    std::unordered_map<std::string, infra::InviteRow> inv_map;
    if (inv_res.ok()) {
      for (auto& row : inv_res.value()) {
        inv_map[row.invited_uid] = std::move(row);
      }
    }

    crow::json::wvalue v;
    v["ok"] = true;
    v["tenant_id"] = tenant;
    v["users"] = crow::json::wvalue::list();
    unsigned int idx = 0;
    for (const auto& u : res.value()) {
      crow::json::wvalue uj;
      uj["uid"]        = u.uid;
      uj["given_name"] = u.given_name;
      uj["surname"]    = u.surname;
      uj["mail"]       = u.mail;

      auto it = inv_map.find(u.uid);
      if (it != inv_map.end()) {
        const auto& inv = it->second;
        uj["invite_id"]          = inv.invite_id;
        uj["invite_status"]      = static_cast<int>(inv.status);
        uj["invite_status_name"] = InviteStatusName(inv.status);
        uj["invite_expires_at"]  = inv.expires_at;
        uj["invite_created_at"]  = inv.created_at;
      } else {
        uj["invite_status"]      = -1;
        uj["invite_status_name"] = "None";
        uj["invite_expires_at"]  = 0;
        uj["invite_created_at"]  = 0;
      }

      uj["hosts"] = crow::json::wvalue::list();
      unsigned int hidx = 0;
      for (const auto& h : u.hosts) {
        crow::json::wvalue hj;
        hj["dn"]       = h.dn;
        hj["hostname"] = h.hostname;
        hj["ip"]       = h.ip;
        uj["hosts"][hidx++] = std::move(hj);
      }
      v["users"][idx++] = std::move(uj);
    }
    return Json(200, v);
  });
}

}  // namespace gatehouse::app
