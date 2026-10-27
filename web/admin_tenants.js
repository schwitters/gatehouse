
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
