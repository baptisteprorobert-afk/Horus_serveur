"use strict";
/* ============================================================
   Serveur de synchronisation Horus (un seul praticien)
   - Node.js (>= 20) + PostgreSQL
   - Variables d'environnement :
       DATABASE_URL (ou POSTGRESQL_ADDON_URI) : adresse de la base PostgreSQL
       JWT_SECRET      : texte secret long et aléatoire (32 caractères minimum)
       SETUP_CODE      : code secret pour créer le compte administrateur la première fois
                         (il sert aussi à récupérer l'accès administrateur : garde-le secret)
       MAX_USERS       : nombre maximum de praticiens (20 par défaut)
       ALLOWED_ORIGIN  : adresse de l'application, ex. https://mon-site.netlify.app
                         (plusieurs adresses possibles, séparées par des virgules)
       PORT            : fourni par l'hébergeur
       PGSSL=1         : seulement si ton hébergeur impose une connexion SSL à la base
   ============================================================ */
const http = require("http");
const crypto = require("crypto");

const COLLECTIONS = new Set(["patients", "agenda", "plages", "closures", "exerciseCatalog", "meta"]);
const ID_RE = /^[\w-]{1,80}$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const MAX_BODY = 12 * 1024 * 1024, MAX_DOC = 4 * 1024 * 1024, MAX_BATCH = 100;
const TOKEN_MS = 30 * 24 * 3600 * 1000, INVITE_MS = 7 * 24 * 3600 * 1000;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";   // sans I, L, O, 0, 1 (confusions)

function b64u(s){ return Buffer.from(s).toString("base64url"); }
function sign(payload, secret){
  const body = b64u(JSON.stringify(payload));
  return body + "." + crypto.createHmac("sha256", secret).update(body).digest("base64url");
}
function verify(token, secret){
  if(typeof token !== "string") return null;
  const i = token.indexOf(".");
  if(i < 1) return null;
  const body = token.slice(0, i), mac = Buffer.from(token.slice(i + 1)), exp = Buffer.from(crypto.createHmac("sha256", secret).update(body).digest("base64url"));
  if(mac.length !== exp.length || !crypto.timingSafeEqual(mac, exp)) return null;
  try{
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return (p && p.exp && p.exp > Date.now()) ? p : null;
  }catch(e){ return null; }
}
function hashPassword(pw){
  const salt = crypto.randomBytes(16);
  return "scrypt$" + salt.toString("base64") + "$" + crypto.scryptSync(pw, salt, 64).toString("base64");
}
function checkPassword(pw, stored){
  const p = String(stored).split("$");
  if(p[0] !== "scrypt" || p.length !== 3) return false;
  const exp = Buffer.from(p[2], "base64"), h = crypto.scryptSync(pw, Buffer.from(p[1], "base64"), 64);
  return h.length === exp.length && crypto.timingSafeEqual(h, exp);
}
function newCode(){
  let c = "";
  for(let i = 0; i < 12; i++){ c += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)]; if(i % 4 === 3 && i < 11) c += "-"; }
  return c;
}
function normCode(c){ return String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, ""); }
function safeEq(a, b){
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

async function initDb(pool){
  await pool.query("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, created_at TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'praticien', active BOOLEAN NOT NULL DEFAULT true, token_ver INTEGER NOT NULL DEFAULT 0, last_login TEXT, last_seen TEXT)");
  await pool.query("CREATE TABLE IF NOT EXISTS invites (id SERIAL PRIMARY KEY, code_hash TEXT UNIQUE NOT NULL, email TEXT NOT NULL, kind TEXT NOT NULL, user_id INTEGER, expires_at TEXT NOT NULL, used BOOLEAN NOT NULL DEFAULT false, created_by INTEGER, created_at TEXT NOT NULL)");
  await pool.query("CREATE TABLE IF NOT EXISTS docs (user_id INTEGER NOT NULL, c TEXT NOT NULL, id TEXT NOT NULL, data JSONB, updated_at TEXT NOT NULL, deleted BOOLEAN NOT NULL DEFAULT false, rev BIGINT NOT NULL, PRIMARY KEY (user_id, c, id))");
  await pool.query("CREATE INDEX IF NOT EXISTS docs_rev_idx ON docs (user_id, rev)");
  await pool.query("CREATE TABLE IF NOT EXISTS rev_counter (id INTEGER PRIMARY KEY, v BIGINT NOT NULL)");
  const rc = await pool.query("SELECT COUNT(*) AS n FROM rev_counter");
  if(Number(rc.rows[0].n) === 0) await pool.query("INSERT INTO rev_counter (id, v) VALUES (1, 0)");
  await pool.query("CREATE TABLE IF NOT EXISTS audit (id SERIAL PRIMARY KEY, at TEXT NOT NULL, kind TEXT NOT NULL, email TEXT, ip TEXT, ok BOOLEAN NOT NULL)");
}

function createApp(pool, cfg){
  const fails = new Map();   // limitation des essais de connexion
  let writeChain = Promise.resolve();   // une seule écriture à la fois (numéro de version cohérent)

  async function audit(kind, email, ip, ok){
    try{
      await pool.query("INSERT INTO audit (at, kind, email, ip, ok) VALUES ($1, $2, $3, $4, $5)", [new Date().toISOString(), kind, String(email || "").slice(0, 120), String(ip || "").slice(0, 64), !!ok]);
      const m = await pool.query("SELECT MAX(id) AS m FROM audit");
      await pool.query("DELETE FROM audit WHERE id < $1", [Number(m.rows[0].m || 0) - 2000]);
    }catch(e){ console.error("audit:", e.message); }
  }
  function clientIp(req){ return String((req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")).split(",")[0].trim(); }
  function originAllowed(origin){ return !!origin && cfg.origins.indexOf(origin) !== -1; }

  function send(req, res, code, obj){
    const body = JSON.stringify(obj);
    const h = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Strict-Transport-Security": "max-age=31536000", "Content-Length": Buffer.byteLength(body) };
    const origin = req.headers.origin;
    if(originAllowed(origin)){ h["Access-Control-Allow-Origin"] = origin; h["Vary"] = "Origin"; }
    res.writeHead(code, h);
    res.end(body);
  }
  function fail(req, res, code, error, message){ send(req, res, code, { error: error, message: message }); }

  function readBody(req){
    return new Promise(function(resolve, reject){
      let size = 0; const chunks = [];
      req.on("data", function(c){ size += c.length; if(size > MAX_BODY){ reject({ code: 413, error: "trop_gros", message: "Envoi trop volumineux." }); req.destroy(); return; } chunks.push(c); });
      req.on("end", function(){
        try{ resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); }
        catch(e){ reject({ code: 400, error: "json_invalide", message: "Requête illisible." }); }
      });
      req.on("error", function(){ reject({ code: 400, error: "requete", message: "Requête interrompue." }); });
    });
  }
  async function authUser(req){
    const h = String(req.headers.authorization || "");
    const p = h.startsWith("Bearer ") ? verify(h.slice(7), cfg.secret) : null;
    if(!p) return null;
    const r = await pool.query("SELECT id, email, role, active, token_ver, last_seen FROM users WHERE id = $1", [p.u]);
    const u = r.rows[0];
    if(!u || !u.active || Number(u.token_ver) !== Number(p.v)) return null;
    const nowIso = new Date().toISOString();
    if(!u.last_seen || Date.parse(nowIso) - Date.parse(u.last_seen) > 10 * 60 * 1000) await pool.query("UPDATE users SET last_seen = $1 WHERE id = $2", [nowIso, u.id]);
    return { id: u.id, email: u.email, role: u.role };
  }
  function newToken(u){ return sign({ u: u.id, v: Number(u.token_ver || 0), exp: Date.now() + TOKEN_MS }, cfg.secret); }
  function codeHash(code){ return crypto.createHmac("sha256", cfg.secret).update(normCode(code)).digest("hex"); }
  async function createInvite(email, kind, userId, createdBy){
    const code = newCode(), exp = new Date(Date.now() + INVITE_MS).toISOString();
    await pool.query("DELETE FROM invites WHERE used = false AND email = $1 AND kind = $2", [email, kind]);
    await pool.query("INSERT INTO invites (code_hash, email, kind, user_id, expires_at, used, created_by, created_at) VALUES ($1, $2, $3, $4, $5, false, $6, $7)", [codeHash(code), email, kind, userId || null, exp, createdBy || null, new Date().toISOString()]);
    return { code: code, expiresAt: exp };
  }
  async function takeInvite(code, email, kind){
    const r = await pool.query("SELECT id, email, user_id, expires_at, used FROM invites WHERE code_hash = $1 AND kind = $2", [codeHash(code), kind]);
    const inv = r.rows[0];
    if(!inv || inv.used || inv.expires_at < new Date().toISOString() || inv.email !== email) return null;
    return inv;
  }
  function checkLock(key){
    const f = fails.get(key);
    return !!(f && f.until && f.until > Date.now());
  }
  function addFail(key){
    const f = fails.get(key) || { n: 0, until: 0 };
    f.n++;
    if(f.n >= 5){ f.until = Date.now() + 15 * 60 * 1000; f.n = 0; }
    fails.set(key, f);
  }

  async function nextRev(){
    const r = await pool.query("UPDATE rev_counter SET v = v + 1 WHERE id = 1 RETURNING v");
    return Number(r.rows[0].v);
  }
  async function currentRev(){
    const r = await pool.query("SELECT v FROM rev_counter WHERE id = 1");
    return Number(r.rows[0].v);
  }

  async function handle(req, res){
    const url = new URL(req.url, "http://x"), path = url.pathname, ip = clientIp(req), origin = req.headers.origin;
    // CORS
    if(req.method === "OPTIONS"){
      if(originAllowed(origin)){
        res.writeHead(204, { "Access-Control-Allow-Origin": origin, "Vary": "Origin", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "600" });
      } else res.writeHead(403);
      res.end(); return;
    }
    if(path === "/health" && req.method === "GET"){ send(req, res, 200, { ok: true }); return; }
    if(origin && !originAllowed(origin)){ fail(req, res, 403, "origine_refusee", "Origine non autorisée."); return; }

    if(path === "/api/status" && req.method === "GET"){
      const r = await pool.query("SELECT COUNT(*) AS n FROM users");
      send(req, res, 200, { setupDone: Number(r.rows[0].n) > 0 }); return;
    }
    if(path === "/api/setup" && req.method === "POST"){
      const b = await readBody(req), key = "setup|" + ip;
      if(checkLock(key)){ fail(req, res, 429, "trop_d_essais", "Trop d'essais : réessaie dans 15 minutes."); return; }
      const n = Number((await pool.query("SELECT COUNT(*) AS n FROM users")).rows[0].n);
      if(n > 0){ fail(req, res, 409, "deja_configure", "Le serveur est déjà installé : connecte-toi, ou utilise un code d'invitation."); return; }
      if(!cfg.setupCode || !safeEq(b.setupCode || "", cfg.setupCode)){ addFail(key); await audit("setup", b.email, ip, false); fail(req, res, 403, "code_invalide", "Code d'installation incorrect."); return; }
      if(!EMAIL_RE.test(String(b.email || ""))){ fail(req, res, 400, "email_invalide", "Adresse e-mail invalide."); return; }
      if(typeof b.password !== "string" || b.password.length < 12){ fail(req, res, 400, "mot_de_passe_faible", "Le mot de passe doit contenir au moins 12 caractères."); return; }
      const email = String(b.email).trim().toLowerCase();
      const r = await pool.query("INSERT INTO users (email, pass, created_at, role, active, token_ver, last_login) VALUES ($1, $2, $3, 'admin', true, 0, $3) RETURNING id", [email, hashPassword(b.password), new Date().toISOString()]);
      await audit("setup", email, ip, true);
      send(req, res, 200, { token: newToken({ id: r.rows[0].id, token_ver: 0 }), email: email, role: "admin" }); return;
    }
    if(path === "/api/login" && req.method === "POST"){
      const b = await readBody(req), email = String(b.email || "").trim().toLowerCase(), key = "login|" + ip + "|" + email;
      if(checkLock(key)){ fail(req, res, 429, "trop_d_essais", "Trop d'essais : réessaie dans 15 minutes."); return; }
      const r = await pool.query("SELECT id, pass, role, active, token_ver FROM users WHERE email = $1", [email]);
      const ok = r.rows.length === 1 && typeof b.password === "string" && checkPassword(b.password, r.rows[0].pass);
      if(!ok){ addFail(key); await audit("login", email, ip, false); fail(req, res, 401, "identifiants_invalides", "E-mail ou mot de passe incorrect."); return; }
      if(!r.rows[0].active){ await audit("login-desactive", email, ip, false); fail(req, res, 403, "compte_desactive", "Ce compte est désactivé : contacte l'administrateur."); return; }
      fails.delete(key);
      await pool.query("UPDATE users SET last_login = $1 WHERE id = $2", [new Date().toISOString(), r.rows[0].id]);
      await audit("login", email, ip, true);
      send(req, res, 200, { token: newToken(r.rows[0]), email: email, role: r.rows[0].role }); return;
    }
    if((path === "/api/join" || path === "/api/reset") && req.method === "POST"){
      const b = await readBody(req), email = String(b.email || "").trim().toLowerCase(), kind = path === "/api/join" ? "join" : "reset", key = "code|" + ip;
      if(checkLock(key)){ fail(req, res, 429, "trop_d_essais", "Trop d'essais : réessaie dans 15 minutes."); return; }
      if(typeof b.password !== "string" || b.password.length < 12){ fail(req, res, 400, "mot_de_passe_faible", "Le mot de passe doit contenir au moins 12 caractères."); return; }
      const inv = await takeInvite(b.code, email, kind);
      if(!inv){ addFail(key); await audit(kind, email, ip, false); fail(req, res, 403, "code_invalide", "Code invalide, expiré ou déjà utilisé (vérifie aussi l'adresse e-mail)."); return; }
      let user;
      if(kind === "join"){
        if(!EMAIL_RE.test(email)){ fail(req, res, 400, "email_invalide", "Adresse e-mail invalide."); return; }
        const ex = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
        if(ex.rows.length){ fail(req, res, 409, "deja_existant", "Un compte existe déjà avec cet e-mail : connecte-toi."); return; }
        const r = await pool.query("INSERT INTO users (email, pass, created_at, role, active, token_ver, last_login) VALUES ($1, $2, $3, 'praticien', true, 0, $3) RETURNING id", [email, hashPassword(b.password), new Date().toISOString()]);
        user = { id: r.rows[0].id, token_ver: 0, role: "praticien" };
      } else {
        const ur = await pool.query("SELECT id, role, token_ver FROM users WHERE id = $1", [inv.user_id]);
        if(!ur.rows.length){ fail(req, res, 403, "code_invalide", "Code invalide, expiré ou déjà utilisé."); return; }
        const ver = Number(ur.rows[0].token_ver) + 1;
        await pool.query("UPDATE users SET pass = $1, token_ver = $2, last_login = $3 WHERE id = $4", [hashPassword(b.password), ver, new Date().toISOString(), inv.user_id]);
        user = { id: inv.user_id, token_ver: ver, role: ur.rows[0].role };
      }
      await pool.query("UPDATE invites SET used = true WHERE id = $1", [inv.id]);
      fails.delete(key);
      await audit(kind, email, ip, true);
      send(req, res, 200, { token: newToken(user), email: email, role: user.role }); return;
    }
    if(path === "/api/admin-recover" && req.method === "POST"){
      const b = await readBody(req), key = "recover|" + ip, email = String(b.email || "").trim().toLowerCase();
      if(checkLock(key)){ fail(req, res, 429, "trop_d_essais", "Trop d'essais : réessaie dans 15 minutes."); return; }
      const r = await pool.query("SELECT id, token_ver FROM users WHERE email = $1 AND role = 'admin'", [email]);
      if(!cfg.setupCode || !safeEq(b.setupCode || "", cfg.setupCode) || !r.rows.length){ addFail(key); await audit("recover", email, ip, false); fail(req, res, 403, "code_invalide", "Code incorrect ou compte administrateur introuvable."); return; }
      if(typeof b.password !== "string" || b.password.length < 12){ fail(req, res, 400, "mot_de_passe_faible", "Le mot de passe doit contenir au moins 12 caractères."); return; }
      const ver = Number(r.rows[0].token_ver) + 1;
      await pool.query("UPDATE users SET pass = $1, token_ver = $2, active = true WHERE id = $3", [hashPassword(b.password), ver, r.rows[0].id]);
      await audit("recover", email, ip, true);
      send(req, res, 200, { token: newToken({ id: r.rows[0].id, token_ver: ver }), email: email, role: "admin" }); return;
    }

    // ----- à partir d'ici : connexion obligatoire -----
    const me = await authUser(req), uid = me && me.id;
    if(!me){ fail(req, res, 401, "non_connecte", "Connexion requise."); return; }

    if(path === "/api/me" && req.method === "GET"){ send(req, res, 200, { email: me.email, role: me.role }); return; }
    if(path === "/api/password" && req.method === "POST"){
      const b = await readBody(req);
      const r = await pool.query("SELECT pass, token_ver FROM users WHERE id = $1", [uid]);
      if(typeof b.oldPassword !== "string" || !checkPassword(b.oldPassword, r.rows[0].pass)){ await audit("password", me.email, ip, false); fail(req, res, 401, "identifiants_invalides", "Mot de passe actuel incorrect."); return; }
      if(typeof b.newPassword !== "string" || b.newPassword.length < 12){ fail(req, res, 400, "mot_de_passe_faible", "Le nouveau mot de passe doit contenir au moins 12 caractères."); return; }
      const ver = Number(r.rows[0].token_ver) + 1;
      await pool.query("UPDATE users SET pass = $1, token_ver = $2 WHERE id = $3", [hashPassword(b.newPassword), ver, uid]);
      await audit("password", me.email, ip, true);
      send(req, res, 200, { ok: true, token: newToken({ id: uid, token_ver: ver }) }); return;
    }

    // ----- administration des praticiens (réservée à l'administrateur) -----
    if(path.startsWith("/api/admin/")){
      if(me.role !== "admin"){ fail(req, res, 403, "reserve_admin", "Réservé à l'administrateur."); return; }
      if(path === "/api/admin/users" && req.method === "GET"){
        const us = await pool.query("SELECT id, email, role, active, created_at, last_login, last_seen FROM users ORDER BY id ASC");
        const cnt = await pool.query("SELECT user_id, COUNT(*) AS n FROM docs WHERE c = 'patients' AND deleted = false GROUP BY user_id");
        const byUser = {}; cnt.rows.forEach(function(x){ byUser[x.user_id] = Number(x.n); });
        const iv = await pool.query("SELECT id, email, kind, expires_at FROM invites WHERE used = false ORDER BY id ASC");
        const nowIso = new Date().toISOString();
        send(req, res, 200, {
          maxUsers: cfg.maxUsers,
          users: us.rows.map(function(u){ return { id: u.id, email: u.email, role: u.role, active: !!u.active, createdAt: u.created_at, lastLogin: u.last_login || "", lastSeen: [u.last_login || "", u.last_seen || ""].sort().pop(), patients: byUser[u.id] || 0, self: u.id === uid }; }),
          invites: iv.rows.filter(function(i){ return i.expires_at > nowIso; }).map(function(i){ return { id: i.id, email: i.email, kind: i.kind, expiresAt: i.expires_at }; })
        }); return;
      }
      if(path === "/api/admin/invite" && req.method === "POST"){
        const b = await readBody(req), email = String(b.email || "").trim().toLowerCase();
        if(!EMAIL_RE.test(email)){ fail(req, res, 400, "email_invalide", "Adresse e-mail invalide."); return; }
        const ex = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
        if(ex.rows.length){ fail(req, res, 409, "deja_existant", "Un compte existe déjà avec cet e-mail."); return; }
        const total = Number((await pool.query("SELECT COUNT(*) AS n FROM users")).rows[0].n) + Number((await pool.query("SELECT COUNT(*) AS n FROM invites WHERE used = false AND kind = 'join' AND email <> $1 AND expires_at > $2", [email, new Date().toISOString()])).rows[0].n);
        if(total >= cfg.maxUsers){ fail(req, res, 409, "limite_atteinte", "Nombre maximum de praticiens atteint (" + cfg.maxUsers + ")."); return; }
        const inv = await createInvite(email, "join", null, uid);
        await audit("admin:invite", email, ip, true);
        send(req, res, 200, inv); return;
      }
      let m = /^\/api\/admin\/invites\/(\d+)\/revoke$/.exec(path);
      if(m && req.method === "POST"){
        await pool.query("DELETE FROM invites WHERE id = $1 AND used = false", [Number(m[1])]);
        await audit("admin:revoke", "", ip, true);
        send(req, res, 200, { ok: true }); return;
      }
      m = /^\/api\/admin\/users\/(\d+)\/(active|reset|delete)$/.exec(path);
      if(m && req.method === "POST"){
        const tid = Number(m[1]), act = m[2], b = await readBody(req);
        const tr = await pool.query("SELECT id, email, role, token_ver FROM users WHERE id = $1", [tid]);
        if(!tr.rows.length){ fail(req, res, 404, "introuvable", "Praticien introuvable."); return; }
        const t = tr.rows[0];
        if(act !== "reset" && tid === uid){ fail(req, res, 400, "action_impossible", "Tu ne peux pas faire cela sur ton propre compte."); return; }
        if(act === "active"){
          const on = !!b.active;
          await pool.query("UPDATE users SET active = $1, token_ver = $2 WHERE id = $3", [on, Number(t.token_ver) + (on ? 0 : 1), tid]);
          await audit(on ? "admin:reactiver" : "admin:desactiver", t.email, ip, true);
          send(req, res, 200, { ok: true }); return;
        }
        if(act === "reset"){
          const inv = await createInvite(t.email, "reset", tid, uid);
          await audit("admin:reset", t.email, ip, true);
          send(req, res, 200, inv); return;
        }
        if(String(b.confirmEmail || "").trim().toLowerCase() !== t.email){ fail(req, res, 400, "confirmation", "Pour supprimer, retape l'adresse e-mail du praticien."); return; }
        await pool.query("DELETE FROM docs WHERE user_id = $1", [tid]);
        await pool.query("DELETE FROM invites WHERE user_id = $1 OR email = $2", [tid, t.email]);
        await pool.query("DELETE FROM users WHERE id = $1", [tid]);
        await audit("admin:supprimer", t.email, ip, true);
        send(req, res, 200, { ok: true }); return;
      }
      fail(req, res, 404, "introuvable", "Adresse inconnue."); return;
    }

    if(path === "/api/sync" && req.method === "GET"){
      const since = Math.max(0, parseInt(url.searchParams.get("since")) || 0), limit = Math.min(200, Math.max(1, parseInt(url.searchParams.get("limit")) || 100));
      const r = await pool.query("SELECT c, id, data, updated_at, deleted, rev FROM docs WHERE user_id = $1 AND rev > $2 ORDER BY rev ASC LIMIT $3", [uid, since, limit + 1]);
      const more = r.rows.length > limit, rows = r.rows.slice(0, limit);
      send(req, res, 200, { rev: await currentRev(), more: more, docs: rows.map(function(d){ return { c: d.c, id: d.id, data: d.deleted ? null : d.data, updatedAt: d.updated_at, deleted: !!d.deleted, rev: Number(d.rev) }; }) }); return;
    }
    if(path === "/api/sync" && req.method === "POST"){
      const b = await readBody(req);
      if(!Array.isArray(b.docs) || b.docs.length > MAX_BATCH){ fail(req, res, 400, "lot_invalide", "Lot de documents invalide (100 maximum)."); return; }
      for(const d of b.docs){
        if(!d || !COLLECTIONS.has(d.c) || typeof d.id !== "string" || !ID_RE.test(d.id) || typeof d.updatedAt !== "string" || d.updatedAt.length > 40){ fail(req, res, 400, "document_invalide", "Document invalide."); return; }
        if(!d.deleted && (typeof d.data !== "object" || d.data === null || JSON.stringify(d.data).length > MAX_DOC)){ fail(req, res, 400, "document_invalide", "Document invalide ou trop volumineux."); return; }
      }
      const result = await (writeChain = writeChain.then(async function(){
        const accepted = [], rejected = [];
        for(const d of b.docs){
          const ex = await pool.query("SELECT updated_at FROM docs WHERE user_id = $1 AND c = $2 AND id = $3", [uid, d.c, d.id]);
          if(ex.rows.length && !(d.updatedAt > ex.rows[0].updated_at)){ rejected.push({ c: d.c, id: d.id, reason: "plus_ancien" }); continue; }
          const rev = await nextRev(), data = d.deleted ? null : JSON.stringify(d.data);
          if(ex.rows.length) await pool.query("UPDATE docs SET data = $1, updated_at = $2, deleted = $3, rev = $4 WHERE user_id = $5 AND c = $6 AND id = $7", [data, d.updatedAt, !!d.deleted, rev, uid, d.c, d.id]);
          else await pool.query("INSERT INTO docs (user_id, c, id, data, updated_at, deleted, rev) VALUES ($1, $2, $3, $4, $5, $6, $7)", [uid, d.c, d.id, data, d.updatedAt, !!d.deleted, rev]);
          accepted.push({ c: d.c, id: d.id });
        }
        return { accepted: accepted, rejected: rejected, rev: await currentRev() };
      }).catch(function(e){ writeChain = Promise.resolve(); throw e; }));
      send(req, res, 200, result); return;
    }
    if(path === "/api/export" && req.method === "GET"){
      const r = await pool.query("SELECT c, id, data, updated_at, deleted, rev FROM docs WHERE user_id = $1 ORDER BY rev ASC", [uid]);
      await audit("export", "", ip, true);
      send(req, res, 200, { exportedAt: new Date().toISOString(), docs: r.rows.map(function(d){ return { c: d.c, id: d.id, data: d.deleted ? null : d.data, updatedAt: d.updated_at, deleted: !!d.deleted, rev: Number(d.rev) }; }) }); return;
    }
    fail(req, res, 404, "introuvable", "Adresse inconnue.");
  }

  return http.createServer(function(req, res){
    handle(req, res).catch(function(e){
      if(e && e.code && e.error){ try{ fail(req, res, e.code, e.error, e.message); }catch(x){} return; }
      console.error("erreur:", e && e.message);
      try{ fail(req, res, 500, "erreur_serveur", "Erreur du serveur."); }catch(x){}
    });
  });
}

function configFromEnv(env){
  return {
    maxUsers: Math.max(1, parseInt(env.MAX_USERS) || 20),
    port: parseInt(env.PORT) || 8080,
    dbUrl: env.DATABASE_URL || env.POSTGRESQL_ADDON_URI || "",
    secret: env.JWT_SECRET || "",
    setupCode: env.SETUP_CODE || "",
    origins: String(env.ALLOWED_ORIGIN || "").split(",").map(function(s){ return s.trim().replace(/\/$/, ""); }).filter(Boolean),
    ssl: env.PGSSL === "1"
  };
}

module.exports = { createApp, initDb, configFromEnv, hashPassword, checkPassword, sign, verify };

if(require.main === module){
  const cfg = configFromEnv(process.env);
  if(!cfg.dbUrl){ console.error("DATABASE_URL manquant."); process.exit(1); }
  if(cfg.secret.length < 32){ console.error("JWT_SECRET manquant ou trop court (32 caractères minimum)."); process.exit(1); }
  if(!cfg.origins.length) console.warn("ALLOWED_ORIGIN vide : aucune application ne pourra se connecter.");
  const { Pool } = require("pg");
  const pool = new Pool({ connectionString: cfg.dbUrl, ssl: cfg.ssl ? { rejectUnauthorized: false } : undefined, max: 5 });
  initDb(pool).then(function(){
    const server = createApp(pool, cfg);
    server.listen(cfg.port, function(){ console.log("Serveur Horus prêt sur le port " + cfg.port); });
    process.on("SIGTERM", function(){ server.close(function(){ pool.end().then(function(){ process.exit(0); }); }); });
  }).catch(function(e){ console.error("Démarrage impossible :", e.message); process.exit(1); });
}
