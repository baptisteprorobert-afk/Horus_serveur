"use strict";
/* ============================================================
   Serveur de synchronisation Horus (un seul praticien)
   - Node.js (>= 20) + PostgreSQL
   - Variables d'environnement :
       DATABASE_URL (ou POSTGRESQL_ADDON_URI) : adresse de la base PostgreSQL
       JWT_SECRET      : texte secret long et aléatoire (32 caractères minimum)
       SETUP_CODE      : code à usage unique pour créer le compte la première fois
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
const TOKEN_MS = 30 * 24 * 3600 * 1000;

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
function safeEq(a, b){
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

async function initDb(pool){
  await pool.query("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, created_at TEXT NOT NULL)");
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
  function auth(req){
    const h = String(req.headers.authorization || "");
    const p = h.startsWith("Bearer ") ? verify(h.slice(7), cfg.secret) : null;
    return p ? p.u : null;
  }
  function newToken(userId){ return sign({ u: userId, exp: Date.now() + TOKEN_MS }, cfg.secret); }
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
      if(n > 0){ fail(req, res, 409, "deja_configure", "Le compte existe déjà : connecte-toi."); return; }
      if(!cfg.setupCode || !safeEq(b.setupCode || "", cfg.setupCode)){ addFail(key); await audit("setup", b.email, ip, false); fail(req, res, 403, "code_invalide", "Code d'installation incorrect."); return; }
      if(!EMAIL_RE.test(String(b.email || ""))){ fail(req, res, 400, "email_invalide", "Adresse e-mail invalide."); return; }
      if(typeof b.password !== "string" || b.password.length < 12){ fail(req, res, 400, "mot_de_passe_faible", "Le mot de passe doit contenir au moins 12 caractères."); return; }
      const email = String(b.email).trim().toLowerCase();
      const r = await pool.query("INSERT INTO users (email, pass, created_at) VALUES ($1, $2, $3) RETURNING id", [email, hashPassword(b.password), new Date().toISOString()]);
      await audit("setup", email, ip, true);
      send(req, res, 200, { token: newToken(r.rows[0].id), email: email }); return;
    }
    if(path === "/api/login" && req.method === "POST"){
      const b = await readBody(req), email = String(b.email || "").trim().toLowerCase(), key = "login|" + ip + "|" + email;
      if(checkLock(key)){ fail(req, res, 429, "trop_d_essais", "Trop d'essais : réessaie dans 15 minutes."); return; }
      const r = await pool.query("SELECT id, pass FROM users WHERE email = $1", [email]);
      const ok = r.rows.length === 1 && typeof b.password === "string" && checkPassword(b.password, r.rows[0].pass);
      if(!ok){ addFail(key); await audit("login", email, ip, false); fail(req, res, 401, "identifiants_invalides", "E-mail ou mot de passe incorrect."); return; }
      fails.delete(key);
      await audit("login", email, ip, true);
      send(req, res, 200, { token: newToken(r.rows[0].id), email: email }); return;
    }

    // ----- à partir d'ici : connexion obligatoire -----
    const uid = auth(req);
    if(!uid){ fail(req, res, 401, "non_connecte", "Connexion requise."); return; }

    if(path === "/api/password" && req.method === "POST"){
      const b = await readBody(req);
      const r = await pool.query("SELECT pass, email FROM users WHERE id = $1", [uid]);
      if(!r.rows.length || typeof b.oldPassword !== "string" || !checkPassword(b.oldPassword, r.rows[0].pass)){ await audit("password", r.rows[0] && r.rows[0].email, ip, false); fail(req, res, 401, "identifiants_invalides", "Mot de passe actuel incorrect."); return; }
      if(typeof b.newPassword !== "string" || b.newPassword.length < 12){ fail(req, res, 400, "mot_de_passe_faible", "Le nouveau mot de passe doit contenir au moins 12 caractères."); return; }
      await pool.query("UPDATE users SET pass = $1 WHERE id = $2", [hashPassword(b.newPassword), uid]);
      await audit("password", r.rows[0].email, ip, true);
      send(req, res, 200, { ok: true }); return;
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
