# Gatehouse

Now includes:
- Kerberos web-login -> encrypted ccache in ticket_vault
- `/api/portal/connect` returns:
  - `otp` for XRDP login (one-time, ~60s)
  - `token` for `/xrdp/krb/fetch` (one-time, ~120s)
- Internal endpoints (shared secret header):
  - `POST /xrdp/otp/verify`
  - `POST /xrdp/krb/fetch`

## Required env vars
```bash
export GATEHOUSE_MASTER_KEY_HEX="$(openssl rand -hex 32)"
export GATEHOUSE_INTERNAL_SECRET="$(openssl rand -hex 24)"
