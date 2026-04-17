#include "app/routes.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "app/http_utils.h"
#include "app/server_context.h"
#include "core/aes_cbc.h"
#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/sha256.h"
#include "core/time.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/cred_fetch_token_repo.h"

namespace gatehouse::app {

namespace {

// Derives key material from the guacamole secret.
// If the secret is valid hex (as Guacamole's json-secret-key requires), it is
// hex-decoded.  Otherwise raw UTF-8 bytes are used as fallback.
// Returns the full decoded bytes — callers truncate as needed.
std::vector<std::uint8_t> DecodeGuacSecret(const std::string& secret) {
  auto decoded = core::HexDecode(secret);
  if (decoded.ok() && !decoded.value().empty()) {
    return decoded.value();
  }
  return std::vector<std::uint8_t>(secret.begin(), secret.end());
}

// Percent-encodes characters that are unsafe in a query-string value.
// Standard Base64 uses '+', '/', '=' — '+' in particular is decoded as space
// by URL parsers, which breaks Guacamole's base64 decoding.
std::string UrlEncodeParam(const std::string& s) {
  std::string out;
  out.reserve(s.size() * 3);
  for (std::size_t i = 0; i < s.size(); ++i) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
      out += static_cast<char>(c);
    } else {
      char buf[4];
      std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned>(c));
      out += buf;
    }
  }
  return out;
}

// Escapes a string for safe embedding in a JSON string literal.
std::string JsonStr(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    if (c == '"')  { out += "\\\""; }
    else if (c == '\\') { out += "\\\\"; }
    else if (c == '\n') { out += "\\n"; }
    else if (c == '\r') { out += "\\r"; }
    else if (c == '\t') { out += "\\t"; }
    else { out.push_back(static_cast<char>(c)); }
  }
  return out;
}

// Builds the Guacamole Encrypted JSON payload and returns the full redirect URL.
// protocol must be "rdp" or "ssh".
core::Result<std::string> BuildGuacUrl(
    const std::string& guacamole_url,
    const std::string& guacamole_secret,
    const std::string& uid,
    const std::string& hostname,
    const std::string& host_ip,
    const std::string& protocol,
    const std::string& token_hex,
    std::int64_t expires_unix_s) {

  const std::string port = (protocol == "rdp") ? "3389" : "22";
  // expires in Guacamole is milliseconds since epoch
  const std::int64_t expires_ms = expires_unix_s * 1000;

  std::string json = "{";
  json += "\"username\":\"" + JsonStr(uid) + "\",";
  json += "\"expires\":" + std::to_string(expires_ms) + ",";
  json += "\"connections\":{";
  json += "\"" + JsonStr(hostname) + "\":{";
  json += "\"protocol\":\"" + JsonStr(protocol) + "\",";

  // --- Start Parameters ---
  json += "\"parameters\":{";
  json += "  \"hostname\":\"" + JsonStr(host_ip.empty() ? hostname : host_ip) + "\",";
  json += "  \"port\":\"" + port + "\",";
  json += "  \"username\":\"" + JsonStr(uid) + "\",";
  json += "  \"password\":\"" + JsonStr(token_hex) + "\",";
  json += "  \"security\":\"rdp\",";
  json += "  \"ignore-cert\":\"true\",";
  json += "  \"server-layout\":\"de-de-qwertz\",";
  json += "  \"width\":\"1920\",";
  json += "  \"height\":\"1080\"";
  json += "},"; // <--- IMPORTANT: The comma indicates another key follows!

  // --- NEW: Start sharingProfiles ---
  json += "\"sharingProfiles\":{";

  // Profile 1: View Only (Read-Only)
  json += "  \"View-Only\":{";
  json += "    \"parameters\":{";
  json += "      \"read-only\":\"true\"";
  json += "    }";
  json += "  },"; // <--- Comma separates the profiles

  // Profile 2: Full Access (Collaboration)
  json += "  \"Full-Access\":{";
  json += "    \"parameters\":{";
  json += "      \"read-only\":\"false\"";
  json += "    }";
  json += "  }"; // <--- No comma after the last profile in this block

  json += "}";
  // --- END sharingProfiles ---

  // Close remaining containers
  json += "}}"; // Closes the specific connection object AND the "connections" object
  json += "}";  // Closes the root object
		//

  std::fprintf(stderr, "[gatehouse][guac] plaintext JSON for uid=%s host=%s: %s\n",
               uid.c_str(), hostname.c_str(), json.c_str());

  const std::vector<std::uint8_t> plaintext(json.begin(), json.end());

  // Guacamole encrypted JSON format (matches Java UserDataService):
  //   1. full_key = HexDecode(secret)        — key length determines AES variant
  //   2. HMAC = HmacSHA256(full_key, json)   — 32-byte signature
  //   3. signed_payload = HMAC || json
  //   4. encrypt = AesCBC(full_key, random_IV, signed_payload)
  //   5. output = Base64(random_IV[16] || ciphertext)
  const std::vector<std::uint8_t> full_key = DecodeGuacSecret(guacamole_secret);

  // Log key for diagnostics.
  {
    std::string k;
    for (std::uint8_t b : full_key) { char buf[3]; std::snprintf(buf,3,"%02x",b); k+=buf; }
    std::fprintf(stderr, "[gatehouse][guac] secret_len=%zu full_key_len=%zu full_key=%s\n",
                 guacamole_secret.size(), full_key.size(), k.c_str());
  }

  // Step 1: HMAC-SHA256 of JSON bytes, keyed with the full decoded key.
  auto hmac = core::HmacSha256(full_key, plaintext);
  if (!hmac.ok()) return core::Result<std::string>::Err(hmac.status());

  // Step 2: signed_payload = HMAC(32 bytes) || json.
  std::vector<std::uint8_t> signed_payload;
  signed_payload.reserve(32 + plaintext.size());
  signed_payload.insert(signed_payload.end(), hmac.value().begin(), hmac.value().end());
  signed_payload.insert(signed_payload.end(), plaintext.begin(), plaintext.end());

  // Step 3: AES-CBC with null IV, key-size-agnostic (32 bytes → AES-256).
  // Java's CryptoService.decrypt() uses a hardcoded NULL_IV; the ciphertext
  // is the entire base64-decoded payload — no IV prepended.
  const std::vector<std::uint8_t> null_iv(16, 0);
  auto enc = core::AesCbcEncryptWithIv(full_key, null_iv, signed_payload);
  if (!enc.ok()) return core::Result<std::string>::Err(enc.status());

  std::fprintf(stderr, "[gatehouse][guac] signed_payload_len=%zu encrypted_len=%zu\n",
               signed_payload.size(), enc.value().size());

  const std::string data = core::Base64Encode(enc.value());

  std::fprintf(stderr, "[gatehouse][guac] base64 payload for uid=%s host=%s: %s\n",
               uid.c_str(), hostname.c_str(), data.c_str());

  // Percent-encode the data parameter: standard Base64 contains '+' which URL
  // parsers decode as space, corrupting the payload before Guacamole sees it.
  std::string url = guacamole_url;
  if (!url.empty() && url.back() == '/') url.pop_back();
  url += "/#/?data=" + UrlEncodeParam(data);

  return core::Result<std::string>::Ok(std::move(url));
}

}  // namespace

void RegisterGuacamoleRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  const std::string& B = ctx.cfg.base_uri;

  // ---- POST /api/me/guacamole-session ----
  // Creates a short-lived credential-fetch token, builds a Guacamole Encrypted
  // JSON payload, and returns the Guacamole URL.
  //
  // Request body (JSON): {"hostname": "...", "protocol": "rdp"|"ssh"}
  // Response (JSON):     {"ok": true, "url": "..."}
  app.route_dynamic(B + "/api/me/guacamole-session")
      .methods("POST"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "unauthenticated";
      return Json(401, v);
    }
    if (!CsrfOkHeader(req, *s)) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "invalid CSRF token";
      return Json(403, v);
    }
    if (ctx.cfg.guacamole_url.empty() || ctx.cfg.guacamole_secret.empty()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "Guacamole not configured";
      return Json(503, v);
    }
    if (!ctx.ldap_dir.has_value()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "LDAP not configured";
      return Json(500, v);
    }

    // Parse JSON body
    auto body = crow::json::load(req.body);
    if (!body) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "invalid JSON body";
      return Json(400, v);
    }
    const std::string hostname = body.has("hostname") ? std::string(body["hostname"].s()) : "";
    const std::string protocol = body.has("protocol") ? std::string(body["protocol"].s()) : "ssh";
    if (hostname.empty()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "hostname required";
      return Json(400, v);
    }
    if (protocol != "rdp" && protocol != "ssh") {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "protocol must be rdp or ssh";
      return Json(400, v);
    }

    // Verify user has access to the requested host and get its IP
    auto hr = ctx.ldap_dir->GetUserHosts(s->tenant_id, s->uid);
    if (!hr.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = hr.status().ToString();
      return Json(502, v);
    }
    std::string host_ip;
    bool found = false;
    for (const auto& h : hr.value()) {
      if (h.hostname == hostname) {
        host_ip = h.ip;
        found = true;
        break;
      }
    }
    if (!found) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "host not found or access denied";
      return Json(403, v);
    }

    // Generate random 32-byte token
    auto token_bytes = core::RandomBytes(32);
    if (!token_bytes.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "random generation failed";
      return Json(500, v);
    }
    const std::string token_hex = core::HexEncode(token_bytes.value());

    // SHA-256 hash to store in DB
    auto token_hash = core::Sha256(token_bytes.value());
    if (!token_hash.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "hash failed";
      return Json(500, v);
    }

    // Generate cft_id
    auto cft_id_bytes = core::RandomBytes(16);
    if (!cft_id_bytes.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "random generation failed";
      return Json(500, v);
    }
    const std::string cft_id = core::HexEncode(cft_id_bytes.value());

    const std::int64_t now = core::UnixNow();
    const std::int64_t expires = now + ctx.cfg.guac_token_ttl_seconds;

    infra::CredFetchTokenRow row;
    row.cft_id = cft_id;
    row.uid = s->uid;
    row.tenant_id = s->tenant_id;
    row.host_id = hostname;
    row.token_hash = token_hash.value();
    row.issued_at = now;
    row.expires_at = expires;
    row.ticket_id = s->ticket_id;

    auto ins = ctx.cred_fetch_tokens.Insert(row);
    if (!ins.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "token store failed";
      return Json(500, v);
    }

    auto url_res = BuildGuacUrl(
        ctx.cfg.guacamole_url, ctx.cfg.guacamole_secret,
        s->uid, hostname, host_ip, protocol, token_hex, expires);
    if (!url_res.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = url_res.status().ToString();
      return Json(500, v);
    }

    crow::json::wvalue v;
    v["ok"] = true;
    v["url"] = url_res.value();
    return Json(200, v);
  });

  // ---- GET /api/cred-fetch/ticket ----
  // Called by the PAM module in the target container.
  // Query params: token=<hex>, uid=<uid>, host=<hostname>
  // Returns: {"ok": true, "ccache_b64": "<base64>"}
  // The Kerberos ticket is deleted from the vault after retrieval (one-time use).
  app.route_dynamic(B + "/api/cred-fetch/ticket")
      .methods("GET"_method)([&ctx](const crow::request& req) {
    const std::string token_hex = req.url_params.get("token") ?
        req.url_params.get("token") : "";
    const std::string uid       = req.url_params.get("uid")   ?
        req.url_params.get("uid")   : "";
    const std::string host      = req.url_params.get("host")  ?
        req.url_params.get("host")  : "";

    if (token_hex.empty() || uid.empty() || host.empty()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "missing parameters";
      return Json(400, v);
    }

    // Decode hex token → raw bytes → SHA-256 hash
    auto token_bytes = core::HexDecode(token_hex);
    if (!token_bytes.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "invalid token encoding";
      return Json(400, v);
    }
    auto token_hash = core::Sha256(token_bytes.value());
    if (!token_hash.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "hash failed";
      return Json(500, v);
    }

    const std::int64_t now = core::UnixNow();
    auto ticket_id_res = ctx.cred_fetch_tokens.VerifyAndConsume(
        uid, host, token_hash.value(), now);
    if (!ticket_id_res.ok()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "token verification failed";
      return Json(500, v);
    }
    if (!ticket_id_res.value().has_value() || ticket_id_res.value()->empty()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "invalid or expired token";
      return Json(401, v);
    }
    const std::string ticket_id = *ticket_id_res.value();

    // Read ticket from vault
    auto vault_row = ctx.ticket_vault_read.GetById(ticket_id);
    if (!vault_row.ok()) {
      std::fprintf(stderr, "[gatehouse][cred-fetch] vault read error for uid=%s: %s\n",
                   uid.c_str(), vault_row.status().ToString().c_str());
      crow::json::wvalue v; v["ok"] = false; v["error"] = "ticket read failed";
      return Json(500, v);
    }
    if (!vault_row.value().has_value()) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "ticket not found";
      return Json(404, v);
    }
    const auto& tvr = *vault_row.value();

    if (tvr.expires_at > 0 && tvr.expires_at < now) {
      crow::json::wvalue v; v["ok"] = false; v["error"] = "ticket expired";
      return Json(401, v);
    }

    // Decrypt ccache
    const std::string_view aad_sv(
        reinterpret_cast<const char*>(tvr.aad.data()), tvr.aad.size());
    auto ccache = core::Aes256GcmDecrypt(
        ctx.master_key, tvr.nonce, aad_sv, tvr.ccache_blob_enc);
    if (!ccache.ok()) {
      std::fprintf(stderr, "[gatehouse][cred-fetch] decrypt error for uid=%s: %s\n",
                   uid.c_str(), ccache.status().ToString().c_str());
      crow::json::wvalue v; v["ok"] = false; v["error"] = "ticket decrypt failed";
      return Json(500, v);
    }

    // Delete ticket (one-time use)
    (void)ctx.vault.Delete(ticket_id);

    const std::string ccache_b64 = core::Base64Encode(ccache.value());

    crow::json::wvalue v;
    v["ok"] = true;
    v["ccache_b64"] = ccache_b64;
    return Json(200, v);
  });
}

}  // namespace gatehouse::app
