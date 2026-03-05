# Gatehouse – Invitations via Live LDAP

Invitations now use **LDAP live lookup** when configured (LDIF remains a dev fallback).

## Debian deps
```bash
sudo apt-get update
sudo apt-get install -y libldap2-dev pkg-config
