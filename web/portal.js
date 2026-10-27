function getCsrfToken(){var m=document.cookie.match(/(^|;)\s*gh_csrf=([^;]+)/);return m?decodeURIComponent(m[2]):''}
async function connectHost(hostname,protocol,btn){
  var lbl=(protocol==='rdp')?'Connect (RDP)':'Connect (SSH)';
  if(btn){btn.disabled=true;btn.textContent='Connecting…';}
  var w=window.open('','_blank');
  if(!w){if(btn){btn.disabled=false;btn.textContent=lbl;}alert('Popup blocked. Please allow popups for this page.');return;}
  const r=await fetch(_B+'/api/me/guacamole-session',{method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':getCsrfToken()},
    body:JSON.stringify({hostname:hostname,protocol:protocol})});
  const j=await r.json();
  if(!r.ok||!j.ok){w.close();if(btn){btn.disabled=false;btn.textContent=lbl;}alert('Connect failed: '+(j.error||r.status));return;}
  w.location.replace(j.launch_url);
  if(btn){setTimeout(function(){btn.disabled=false;btn.textContent=lbl;},4000);}
}
async function loadHosts() {
  const r = await fetch(_B+'/api/me/hosts');
  const div = document.getElementById('hostContainer');
  if (!r.ok) { div.innerHTML = '<p style="color:#b00020">Failed to load hosts.</p>'; return; }
  const j = await r.json();
  if (!j.items || j.items.length === 0) { div.innerHTML = '<p>No managed hosts assigned to you.</p>'; return; }
  const grid = document.createElement('div');
  grid.className = 'host-grid';
  for(const host of j.items) {
    const card = document.createElement('div');
    card.className = 'host-card';
    const b = document.createElement('b');
    b.textContent = host.hostname || 'Unknown Host';
    const p = document.createElement('p');
    p.style.cssText = 'margin:8px 0 0 0';
    const code = document.createElement('code');
    code.textContent = host.ip || 'No IP configured';
    p.appendChild(code);
    const proto=(host.protocol==='rdp')?'rdp':'ssh';
    card.appendChild(b);
    card.appendChild(p);
    if(_GUAC_PROTOS.indexOf(proto)!==-1){
      const btn=document.createElement('button');
      btn.textContent=(proto==='rdp')?'Connect (RDP)':'Connect (SSH)';
      btn.style.cssText='margin-top:10px;padding:6px 12px;font-size:0.85em;width:100%;background:#1a6b38';
      btn.onclick=function(e){connectHost(host.hostname||'',proto,e.currentTarget);};
      card.appendChild(btn);
    }
    grid.appendChild(card);
  }
  div.innerHTML = '';
  div.appendChild(grid);
}
loadHosts();