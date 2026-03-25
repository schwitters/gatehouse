# Security-Audit: gatehouse (Version 500)

**Datum:** 2026-03-11  
**Auditor:** Automatisierte Analyse (CleanCode / CleanArchitecture / Safe Programming)  
**Scope:** Vollständiger Quellcode (C++20, CMake, SQLite, Crow HTTP, OpenLDAP, Kerberos 5, OpenSSL, libcurl)

---

## Zusammenfassung

| Schweregrad | Anzahl |
|-------------|--------|
| 🔴 Kritisch  | 4      |
| 🟠 Hoch      | 6      |
| 🟡 Mittel    | 8      |
| 🔵 Niedrig   | 7      |

---

## 🔴 Kritische Befunde

---

### CRIT-01 · Kein HTTPS erzwungen – Credentials im Klartext übertragbar

**Datei:** `src/app/http_server.cc` (Crow-App-Konfiguration)  
**Code:**
```cpp
crow::SimpleApp app;
app.loglevel(crow::LogLevel::Warning);
// Kein TLS-Zertifikat konfiguriert, kein app.ssl_file(…)
```

**Problem:** Der HTTP-Server wird ohne TLS gestartet. Passwörter beim Login-POST (`/auth/login`), das Kerberos-Password bei `/portal/changepw` sowie der Session-Cookie werden im Klartext übertragen.

**Empfehlung:** `crow::App` mit `.ssl_file(cert, key)` konfigurieren oder einen TLS-Reverse-Proxy (nginx/Caddy) vorschalten und HTTP → HTTPS erzwingen. Alle Cookies müssen zusätzlich das Attribut `; Secure` erhalten.

---

### CRIT-02 · Credentials im Klartext in Umgebungsvariablen (kein Secret-Management)

**Dateien:** `src/app/http_server.cc`, `src/app/email_sender.cc`  
**Code:**
```cpp
// Kerberos Admin-Passwort
const char* env_kadmin_pass = std::getenv("GATEHOUSE_KADM5_ADMIN_PASS");

// SMTP-Passwort
const char* env_pass = std::getenv("GMAIL_APP_PASS");

// Master Encryption Key
const char* p = std::getenv("GATEHOUSE_MASTER_KEY_HEX");
```

**Problem:** Drei hochsensible Secrets (Kerberos Admin-Passwort, SMTP-App-Passwort, AES-Master-Key) werden als Plaintext-Umgebungsvariablen übergeben. In containerisierten Umgebungen (Docker, Kubernetes) sind Env-Variablen häufig in Logs, `/proc/[pid]/environ` oder bei `docker inspect` sichtbar.

**Empfehlung:** Verwendung eines Secret-Stores (HashiCorp Vault, Kubernetes Secrets mit `secretKeyRef`, systemd-Credentials). Den Master-Key niemals als Hex-String bereitstellen – stattdessen als Binärdatei mit restriktiven Dateiberechtigungen lesen.

---

### CRIT-03 · Session-IP-Binding schützt nicht bei Proxies (X-Forwarded-For nicht ausgewertet)

**Datei:** `src/app/http_server.cc`  
**Code:**
```cpp
auto hash_remote_ip = [](const std::string& ip) -> std::vector<std::uint8_t> {
    const std::vector<std::uint8_t> ip_bytes(ip.begin(), ip.end());
    auto h = core::Sha256(ip_bytes);
    return h.ok() ? h.value() : std::vector<std::uint8_t>{};
};
```

**Problem:** Der Code verwendet `req.remote_ip_address`. Beim Betrieb hinter einem Reverse-Proxy ist die `remote_ip_address` immer die Proxy-IP (z. B. `127.0.0.1`). Alle Sessions wären dann an dieselbe IP gebunden und das IP-Binding schützt de facto nicht. Gleichzeitig wird `X-Forwarded-For` nicht validiert – ein Angreifer kann bei manchen Konfigurationen diese Header fälschen.

**Empfehlung:** Einen konfigurierbaren Trusted-Proxy-Mode implementieren. Wenn der Proxy vertrauenswürdig ist, den ersten Eintrag aus `X-Forwarded-For` verwenden. Andernfalls das IP-Binding deaktivieren oder durch eine Session-Challenge ersetzen.

---

### CRIT-04 · `const_cast` bei Kerberos-Passwort – potenzielle Schreiboperation auf `const char*`

**Datei:** `src/infra/krb5_helpers.h`  
**Code:**
```cpp
char* password_mut = const_cast<char*>(password.c_str());
const krb5_error_code rc = krb5_get_init_creds_password(
    ctx, creds, principal, password_mut, ...);
```

**Problem:** `const_cast` auf das interne Buffer eines `std::string` ist undefined behavior, wenn die Kerberos-Bibliothek den Buffer modifiziert (was bei einigen MIT-krb5-Versionen in bestimmten Fehlerpfaden dokumentiert ist). In der Praxis kann dies zu heap corruption führen.

**Empfehlung:** Das Passwort in einen `std::vector<char>` kopieren, der explizit schreibbar ist, und dessen `.data()` übergeben. Anschließend den Buffer mit `OPENSSL_cleanse` oder `explicit_bzero` überschreiben.

---

## 🟠 Hohe Befunde

---

### HIGH-01 · Kein Secure-Flag auf Session-Cookie

**Datei:** `src/app/http_server.cc`  
**Code:**
```cpp
r.add_header("Set-Cookie",
    cfg_.session_cookie_name + "=" + row.sid +
        "; Path=/; Max-Age=…; HttpOnly; SameSite=Lax");
```

**Problem:** Fehlendes `; Secure`-Attribut. Ohne TLS (→ CRIT-01) oder bei Mixed-Content können Cookies über HTTP mitgesendet werden.

**Empfehlung:** `; Secure` zum Cookie-String hinzufügen, sobald TLS aktiv ist.

---

### HIGH-02 · Login-Rate-Limiting nur im Arbeitsspeicher – kein persistentes Brute-Force-Schutz

**Datei:** `src/app/http_server.cc`  
**Code:**
```cpp
std::unordered_map<std::string, std::pair<int, std::int64_t>> login_attempts;
```

**Problem:** Der Zähler lebt im Prozessspeicher. Nach einem Neustart, einem Crash oder bei mehreren Prozess-Instanzen sind alle Zähler zurückgesetzt. Ein Angreifer kann mit 10 Versuchen, dann einem Kill und erneutem Start, unbegrenzt weiter angreifen. Außerdem ist die Map unbegrenzt und wächst bei IP-Spoofing-Flooding ohne Limit (Memory-Exhaustion).

**Empfehlung:** Zähler in SQLite persistieren (eigene Tabelle `login_attempts` mit TTL). Die In-Memory-Map auf eine maximale Größe begrenzen (LRU-Cache-Muster).

---

### HIGH-03 · OTP mit 6 Ziffern und modularem Bias

**Datei:** `src/app/http_server.cc`  
**Code:**
```cpp
const unsigned int v = /* 32 random bits */ ...;
const unsigned int code = (v % 900000U) + 100000U;
```

**Problem:** `UINT_MAX (4294967295) % 900000 = 295295`. Die ersten ~295295 Werte haben eine um 1 höhere Wahrscheinlichkeit (modularer Bias ~0,007 % pro Code). Schwerwiegender: 6-stellige OTPs haben nur 900.000 mögliche Werte. Mit 5 Versuchen (max_attempts) und 10 Minuten Gültigkeit ergibt sich eine Ratewahrscheinlichkeit von 0,00056 %, was für ein Einladungsportal akzeptabel erscheint – aber der Bias sollte eliminiert werden.

**Empfehlung:** Rejection-Sampling verwenden: neue Zufallsbytes ziehen, wenn `v >= (UINT_MAX - UINT_MAX % 900000)`. Alternativ einen CSPRNG-Ansatz über `RAND_bytes` und `BN_rand_range` aus OpenSSL nutzen.

---

### HIGH-04 · Email-Header-Injection möglich

**Datei:** `src/app/email_sender.cc`  
**Code:**
```cpp
const std::string subject_hdr = "Subject: " + spec.subject + "\r\n";
headers = curl_slist_append(headers, subject_hdr.c_str());
```

Ähnlich bei `from_name`, `from_email`, und Empfängeradressen.

**Problem:** Wenn `spec.subject` oder andere Felder Benutzereingaben enthalten (z. B. den `tenant_ou`-Namen aus der Admin-UI), können durch eingebettete `\r\n`-Sequenzen zusätzliche SMTP-Header injiziert werden.

**Empfehlung:** Alle in SMTP-Header eingebetteten Strings auf `\r` und `\n` validieren/entfernen. Eine Hilfsfunktion `SanitizeSmtpHeader(std::string_view)` schreiben, die alle Steuerzeichen strippt.

---

### HIGH-05 · Fehlende Content-Security-Policy (CSP)

**Datei:** `src/app/http_server.cc` (alle `HtmlPage`-Aufrufe)  
**Code:**
```cpp
crow::response HtmlPage(int code, const std::string& html) {
    r.set_header("X-Content-Type-Options", "nosniff");
    r.set_header("X-Frame-Options", "DENY");
    // Kein Content-Security-Policy Header
```

**Problem:** Obwohl `crow::json::escape` in HTML-Ausgaben verwendet wird, fehlt ein CSP-Header vollständig. Inline-JavaScript (`<script>`-Blöcke) im Portal und Admin-UI ist unkontrolliert ausführbar.

**Empfehlung:** Minimalen CSP-Header setzen:  
`Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}'; style-src 'unsafe-inline'`  
Langfristig Inline-JS in externe Dateien auslagern.

---

### HIGH-06 · Invite-OTP-Verifizierung nach erfolgreichem Schritt überspringbar (Race-Condition möglich)

**Datei:** `src/app/http_server.cc`, Route `/invite/complete` (POST)  
**Code:**
```cpp
auto verified_res = invite_otps.IsVerified(is->sid);
const bool verified = verified_res.ok() && verified_res.value();
// … später im POST ohne atomare Transaktion:
(void)invites.UpdateStatus(is->invite_id, infra::InviteStatus::kCompleted, now);
```

**Problem:** Die Überprüfung `IsVerified` und die anschließende Account-Aktivierung (Kerberos + LDAP) laufen nicht in einer Datenbanktransaktion. Bei gleichzeitigen Requests (z. B. zwei Tabs) könnte ein Angreifer die Verifikation umgehen, wenn zwischen `IsVerified` und dem Abschluss ein weiterer Request landet.

**Empfehlung:** Die gesamte Sequence (OTP-Check, Kerberos-Create, LDAP-Activate, Invite-Status-Update) in eine `BEGIN IMMEDIATE` Transaktion wrappen. Mindestens muss der OTP-Status atomar mit dem Invite-Status gesetzt werden.

---

## 🟡 Mittlere Befunde

---

### MED-01 · Passwort-Eingabe wird nicht aus dem Speicher gelöscht (Sensitive Data in Memory)

**Dateien:** `src/app/http_server.cc`, `src/infra/krb5_client.cc`  
**Code:**
```cpp
const std::string old_pw = core::FormGet(req.body, "old_password").value_or("");
const std::string new_pw = core::FormGet(req.body, "new_password").value_or("");
// Nach Verwendung werden die std::string Objekte normal destruiert
```

**Problem:** Passwörter liegen als `std::string` im Stack. Der Destruktor gibt den Speicher frei, überschreibt ihn aber nicht. Core-Dumps oder Swap-Datei-Analysen können diese Daten offenlegen.

**Empfehlung:** Nach der Verwendung mit `OPENSSL_cleanse(pw.data(), pw.size())` überschreiben. Für längerfristige Speicherung eine `SecureString`-Wrapper-Klasse implementieren, die im Destruktor den Buffer löscht.

---

### MED-02 · Hardcodierter absoluter Bibliothekspfad

**Datei:** `CMakeLists.txt`  
**Code:**
```cmake
target_link_libraries(gatehouse PRIVATE
   /lib/x86_64-linux-gnu/libcom_err.so
)
```

**Problem:** Absoluter Pfad verhindert Cross-Compilation und schlägt auf Systemen fehl, auf denen die Bibliothek an einem anderen Ort installiert ist. Ggf. wird in Zukunft eine manipulierte Version an diesem Pfad eingeschleust (Supply Chain Risk auf shared Hosts).

**Empfehlung:** Den Pfad durch `${COM_ERR_LIBRARIES}` aus `pkg_check_modules` ersetzen.

---

### MED-03 · `sqlite3_column_text` ohne NULL-Prüfung dereferenziert

**Datei:** `src/infra/cred_fetch_token_repo.cc`, `src/infra/session_repo.cc`  
**Code:**
```cpp
const std::string cft_id = reinterpret_cast<const char*>(sqlite3_column_text(sel, 0));
const std::string ticket_id = reinterpret_cast<const char*>(sqlite3_column_text(sel, 1));
```

**Problem:** `sqlite3_column_text` kann `nullptr` zurückgeben (bei SQL NULL-Werten oder OOM). Das direkte Übergeben an `std::string(nullptr)` ist undefined behavior und führt zu einem Crash.

**Empfehlung:**
```cpp
auto safe_text = [](sqlite3_stmt* s, int col) -> std::string {
    const auto* t = sqlite3_column_text(s, col);
    return t ? reinterpret_cast<const char*>(t) : "";
};
```

---

### MED-04 · Fehlende Validierung von `invited_uid` vor LDAP/Kerberos-Operationen

**Datei:** `src/app/http_server.cc`, Route `/invite/complete` (POST)  
**Code:**
```cpp
std::string new_princ = inv.value()->invited_uid + "@" + cfg_.auth_cfg.krb5_realm;
auto krc = kadm.CreatePrincipal(new_princ, pwd1, dn_res.value().value());
```

**Problem:** `invited_uid` kommt aus der Datenbank und wurde ursprünglich aus `body["uid"].s()` der Admin-API befüllt. Es gibt keine Validierung gegen einen Whitelist-Zeichensatz. Sonderzeichen wie `/`, `@` oder Leerzeichen in der UID können zu fehlerhaften Kerberos-Prinzipalen führen oder LDAP-DN-Injection ermöglichen.

**Empfehlung:** Alle UIDs gegen einen strikten Regex validieren (z. B. `^[a-z][a-z0-9._-]{0,31}$`) an der Eingabe-Grenze (Admin-API) und erneut vor der LDAP/Kerberos-Operation.

---

### MED-05 · Rate-Limiting für OTP-Send-Endpunkt nur pro Session, nicht per IP

**Datei:** `src/app/http_server.cc`, Route `/invite/otp/send`  
**Code:**
```cpp
if (diff < 60) {
    return RedirectTo("/invite/complete?err=Please+wait+60+seconds...");
}
```

**Problem:** Das Cooldown wird pro `invite_session.sid` geprüft. Ein Angreifer mit Zugriff auf den Invite-Link kann durch schnelles paralleles Erstellen von Invite-Sessions das Cooldown umgehen und beliebig viele OTP-Emails auslösen (Email-Bombing / Ressourcenerschöpfung).

**Empfehlung:** Zusätzlich ein IP-basiertes Rate-Limit für den `/invite/otp/send`-Endpunkt (ähnlich dem Login-Rate-Limiter), und die Anzahl der OTPs pro Invite-Session auf ein Gesamtlimit (z. B. 10) begrenzen.

---

### MED-06 · LDAP-Starttls ohne Certificate-Pinning

**Datei:** `src/infra/ldap_directory.cc`  
**Code:**
```cpp
if (cfg.starttls) {
    int rc = ldap_start_tls_s(ld.get(), nullptr, nullptr);
```

**Problem:** Die Zertifikatsvalidierung des LDAP-Servers hängt von der OpenLDAP-Client-Konfiguration (`/etc/ldap/ldap.conf`) ab, die standardmäßig `TLS_REQCERT allow` (kein Verify) setzen kann. Es gibt keine explizite Konfigurationsoption im Code um `LDAP_OPT_X_TLS_REQUIRE_CERT` zu setzen.

**Empfehlung:** Explizit `ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &LDAP_OPT_X_TLS_DEMAND)` setzen, bevor `ldap_start_tls_s` aufgerufen wird. Den CA-Pfad konfigurierbar machen.

---

### MED-07 · `login_attempts`-Map wächst ohne Limit (DoS durch Speichererschöpfung)

**Datei:** `src/app/http_server.cc`  
**Code:**
```cpp
std::unordered_map<std::string, std::pair<int, std::int64_t>> login_attempts;
auto& entry = login_attempts[ip];
```

**Problem:** Jede einmalig gesehene IP-Adresse erzeugt dauerhaft einen Eintrag. Ein Angreifer mit Zugriff auf viele IPs (Botnet) oder durch IP-Spoofing kann die Map unbegrenzt anwachsen lassen.

**Empfehlung:** Maximale Map-Größe definieren (z. B. 100.000 Einträge). Einträge nach Ablauf des Zeitfensters automatisch löschen oder einen zeitbasierten Cleanup-Thread einrichten.

---

### MED-08 · XSS-Risiko durch unsichere innerHTML-Zuweisung im Admin-JS

**Datei:** `src/app/http_server.cc` (kAdminInvitesPage)  
**Code:**
```javascript
h += '<b>' + (host.hostname || 'Unknown Host') + '</b>';
h += '<p><code>' + (host.ip || 'No IP configured') + '</code></p>';
// Direkt als innerHTML:
div.innerHTML = h;
```

**Problem:** `host.hostname` und `host.ip` kommen aus LDAP-Daten und werden ohne Escaping in innerHTML eingebaut. Falls ein LDAP-Eintrag manipuliert ist (z. B. durch ein LDAP-Injection-Szenario), kann JavaScript im Browser des Admins ausgeführt werden (stored XSS).

**Empfehlung:** Entweder `textContent` statt `innerHTML` verwenden, oder eine serverseitige Escaping-Funktion für JSON-Daten anwenden. `document.createElement` + `.textContent` ist die sicherste Alternative.

---

## 🔵 Niedrige Befunde

---

### LOW-01 · `CurlGlobal` als `static` in Funktion – nicht Thread-safe bei der ersten Initialisierung

**Datei:** `src/app/email_sender.cc`  
**Code:**
```cpp
static CurlGlobal curl_global;
```

`curl_global_init` ist nicht thread-safe. In C++11 sind function-local statics zwar initialisierungssicher, aber `curl_global_init` macht interne C-Library-Initialisierungen, die nicht reentrant sind.

**Empfehlung:** `curl_global_init` einmalig beim Programmstart (in `main.cc`) aufrufen, bevor Threads gestartet werden.

---

### LOW-02 · `open("/dev/urandom")` bei jedem Aufruf statt `getrandom(2)` oder OpenSSL

**Datei:** `src/core/random.cc`  
**Code:**
```cpp
const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
```

**Problem:** Das wiederholte Öffnen von `/dev/urandom` ist ineffizient. Auf sehr alten Kerneln (< 3.17) existiert `getrandom(2)` nicht, aber auf modernen Systemen ist `RAND_bytes` aus OpenSSL die idiomatischere und portablere Lösung, da die Bibliothek bereits verlinkt ist.

**Empfehlung:** `RAND_bytes(out.data(), static_cast<int>(n))` aus OpenSSL verwenden. Fehlerbehandlung mit `ERR_get_error`.

---

### LOW-03 · Kein `HSTS`-Header gesetzt

**Datei:** `src/app/http_server.cc`  
Kein `Strict-Transport-Security`-Header in keiner Response.

**Empfehlung:** Nach Aktivierung von TLS (CRIT-01):  
`Strict-Transport-Security: max-age=31536000; includeSubDomains`

---

### LOW-04 · Schema-Migration ohne Backup-Strategie

**Datei:** `src/infra/migrate.cc`

Migrationen laufen direkt auf der Produktionsdatenbank ohne vorheriges Backup. Ein fehlgeschlagener ALTER TABLE zerstört die Daten, ohne Rollback-Möglichkeit.

**Empfehlung:** Vor jeder Migration eine SQLite-`BACKUP`-API-Kopie erstellen. Transaktionen werden bereits korrekt verwendet, schützen aber nicht vor `PRAGMA user_version`-Drift.

---

### LOW-05 · `std::fprintf(stderr, …)` mit unkontrollierten Strings (keine Format-String-Gefahr, aber Log-Injection)

**Datei:** `src/app/http_server.cc`  
**Code:**
```cpp
std::fprintf(stderr, "[gatehouse][kadm5] Failed to create principal: %s\n",
             krc.status().ToString().c_str());
```

**Problem:** `status().ToString()` enthält ggf. Kerberos-Fehlermeldungen, die Benutzereingaben widerspiegeln. In zentralisierten Logging-Systemen könnte das zu Log-Injection führen (z. B. ANSI-Escape-Sequenzen, die Terminals manipulieren).

**Empfehlung:** Log-Strings sanitisieren (nicht-druckbare Zeichen entfernen oder ersetzen) bevor sie in Logs geschrieben werden.

---

### LOW-06 · Invite-Token nur als Hex in URL – kein PKCE oder Binding an Browser

**Datei:** `src/app/http_server.cc`  

Der Invite-Token (`/invite/accept?token=<hex>`) hat keine Browser-Bindung. Wer den Link kennt (z. B. durch URL-Leak in Proxy-Logs oder Browser-History), kann die Einladung annehmen.

**Empfehlung:** Den Token nach einmaliger Nutzung sofort invalidieren (wird derzeit getan ✓). Zusätzlich die Einladungs-URL nur über sichere Channels übermitteln und die Lebensdauer `invite_ttl_seconds` sorgfältig konfigurieren.

---

### LOW-07 · Fehlende `robots.txt` und Admin-Path-Schutz

**Datei:** `src/app/http_server.cc`

Routen wie `/admin/invites`, `/admin/tenants`, `/api/admin/*` sind für Search-Engine-Crawler sichtbar.

**Empfehlung:** Eine `robots.txt` mit `Disallow: /admin` und `Disallow: /api` ausliefern. Zusätzlich auf API-Endpunkten keine Stack-Traces oder interne Fehlertexte zurückgeben.

---

## Positive Aspekte (Was gut gemacht ist)

- ✅ **SQL-Injection verhindert**: Alle SQLite-Abfragen verwenden `sqlite3_prepare_v2` mit parametrisierten Bindings.
- ✅ **LDAP-Injection verhindert**: `EscapeFilterValue` in `src/infra/ldap_directory.cc` escapet RFC-4515-Sonderzeichen korrekt.
- ✅ **AES-256-GCM für Kerberos-Ticket-Vault**: Korrekte AEAD-Verschlüsselung mit Random-Nonce und AAD über OpenSSL EVP.
- ✅ **CSRF-Schutz**: Konsistente Verwendung von CSRF-Tokens sowohl für Form-POSTs (`_csrf`-Feld) als auch JSON-API-Calls (`X-CSRF-Token`-Header).
- ✅ **Constant-Time-Vergleich für OTP-Hashes**: `CRYPTO_memcmp` in `invite_otp_repo.cc`.
- ✅ **HttpOnly + SameSite auf Session-Cookie**: Verhindert clientseitigen JS-Zugriff.
- ✅ **`BEGIN IMMEDIATE` Transaktionen**: Verhindert Race-Conditions bei Invite-Accept und Token-Consume.
- ✅ **RAII für alle Kerberos- und LDAP-Handles**: `UniqueKrb5Context`, `LdapHandle` etc. verhindern Resource-Leaks.
- ✅ **Compiler-Härtungsflags**: `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wnull-dereference`.
- ✅ **IP-Hash-Binding für Sessions**: SHA256-Hash der Client-IP wird bei der Session-Erstellung gespeichert und bei jedem Request geprüft.

---

## Empfohlene Prioritäten

| Priorität | Maßnahme |
|-----------|----------|
| 1 | CRIT-01: TLS aktivieren, Secure-Flag auf Cookies |
| 2 | CRIT-02: Secret-Manager integrieren |
| 3 | HIGH-04: SMTP-Header-Injection schließen |
| 4 | MED-03: NULL-Prüfung bei `sqlite3_column_text` |
| 5 | CRIT-04: `const_cast` Passwort-Buffer ersetzen |
| 6 | HIGH-06: Invite-Completion atomarisieren |
| 7 | MED-04: UID-Validierung vor LDAP/Kerberos |
| 8 | HIGH-05: Content-Security-Policy Header |

---

*Dieser Report wurde auf Basis einer statischen Quellcodeanalyse erstellt. Eine dynamische Analyse (Fuzzing, DAST, Penetrationstest) ist empfohlen, um weitere Laufzeit-Verwundbarkeiten aufzudecken.*
