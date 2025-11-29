// server.js
const express = require("express");
const axios = require("axios");
const qs = require("qs");
const sqlite3 = require("sqlite3").verbose();
const { open } = require("sqlite");
require("dotenv").config();

const app = express();
app.use(express.json());

// ---------- CONFIG from env ----------
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL; // e.g. https://yourdomain.com
const REDIRECT_PATH = "/productboard/callback";
const REDIRECT_URI = BASE_URL + REDIRECT_PATH;
const PORT = process.env.PORT || 3000;
const PB_AUTH_URL = "https://api.productboard.com/oauth/authorize";
const PB_TOKEN_URL = "https://api.productboard.com/oauth/token";
const PB_API_BASE = "https://api.productboard.com";

// ---------- DB ----------
let db;
(async () => {
  db = await open({ filename: "./db.sqlite3", driver: sqlite3.Database });
  await db.exec(`CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zoho_user_id TEXT UNIQUE,
    access_token TEXT,
    refresh_token TEXT,
    scope TEXT,
    expires_at INTEGER
  );`);
})();

// ---------- Helpers ----------
function epochSeconds() { return Math.floor(Date.now()/1000); }

async function saveTokens(zoho_user_id, tokenResp) {
  const expires_at = epochSeconds() + (tokenResp.expires_in || 3600);
  const q = `INSERT INTO tokens (zoho_user_id, access_token, refresh_token, scope, expires_at)
             VALUES (?,?,?,?,?)
             ON CONFLICT(zoho_user_id) DO UPDATE SET
               access_token=excluded.access_token,
               refresh_token=excluded.refresh_token,
               scope=excluded.scope,
               expires_at=excluded.expires_at;`;
  await db.run(q, [zoho_user_id, tokenResp.access_token, tokenResp.refresh_token || "", tokenResp.scope || "", expires_at]);
}

async function getTokens(zoho_user_id) {
  return db.get(`SELECT * FROM tokens WHERE zoho_user_id = ?`, zoho_user_id);
}

async function refreshIfNeeded(zoho_user_id) {
  const row = await getTokens(zoho_user_id);
  if (!row) throw { status:401, message: "not_connected" };
  const now = epochSeconds();
  // refresh if expiry within 60s
  if (row.expires_at - now > 60) return row;
  // do refresh
  const data = {
    grant_type: "refresh_token",
    refresh_token: row.refresh_token,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET
  };
  const resp = await axios.post(PB_TOKEN_URL, qs.stringify(data), {
    headers: { "Content-Type":"application/x-www-form-urlencoded" }
  });
  await saveTokens(zoho_user_id, resp.data);
  return await getTokens(zoho_user_id);
}

// ---------- Step 1: Login endpoint (open in browser from Cliq) ----------
app.get("/productboard/login", (req, res) => {
  // expected: zoho_user_id param (to tie tokens to Zoho user)
  const zoho_user_id = req.query.zoho_user_id || "anonymous";
  // state used to carry zoho_user_id (URL-safe)
  const state = encodeURIComponent(JSON.stringify({ zoho_user_id }));
  const url = `${PB_AUTH_URL}?client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent("product_hierarchy.read notes.read users.read")}&state=${state}`;
  return res.redirect(url);
});

// ---------- Step 2: Callback (Productboard -> here) ----------
app.get("/productboard/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send("missing_code");
    const parsed = state ? JSON.parse(decodeURIComponent(state)) : {};
    const zoho_user_id = parsed.zoho_user_id || "anonymous";

    const data = {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET
    };

    const tokenResp = await axios.post(PB_TOKEN_URL, qs.stringify(data), {
      headers: { "Content-Type":"application/x-www-form-urlencoded" }
    });

    await saveTokens(zoho_user_id, tokenResp.data);

    // friendly page and instruction to close
    return res.send(`<h3>Productboard connected for user: ${zoho_user_id}</h3>
      <p>Close this window and return to Zoho Cliq.</p>`);
  } catch (err) {
    console.error("callback error:", err.response?.data || err.message || err);
    return res.status(500).send("oauth_exchange_error");
  }
});

// ---------- Helper endpoint for Cliq to check connection ----------
app.get("/productboard/status", async (req,res) => {
  const uid = req.query.zoho_user_id;
  if(!uid) return res.status(400).json({ error: "missing zoho_user_id" });
  const row = await getTokens(uid);
  return res.json({ connected: !!row, expires_at: row ? row.expires_at : null });
});

// ---------- Example proxy API: list features ----------
app.get("/productboard/features", async (req, res) => {
  try {
    const uid = req.query.zoho_user_id;
    if (!uid) return res.status(400).json({ error: "missing zoho_user_id" });

    const tokens = await refreshIfNeeded(uid);
    const resp = await axios.get(`${PB_API_BASE}/features`, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Version": "2",
        Accept: "application/json"
      }
    });
    return res.json(resp.data);
  } catch (err) {
    console.error("features error:", err.response?.data || err.message || err);
    const status = err.status || (err.response ? err.response.status : 500);
    return res.status(status).json({ error: "productboard_api_error", details: err.response?.data || err.message });
  }
});

// ---------- Create note example (POST) ----------
app.post("/productboard/create-note", async (req, res) => {
  try {
    const uid = req.query.zoho_user_id;
    if (!uid) return res.status(400).json({ error: "missing zoho_user_id" });
    const body = req.body || {};
    const tokens = await refreshIfNeeded(uid);
    const resp = await axios.post(`${PB_API_BASE}/notes`, body, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Version": "2",
        "Content-Type": "application/json"
      }
    });
    return res.json(resp.data);
  } catch (err) {
    console.error("create-note error:", err.response?.data || err.message || err);
    return res.status(500).json({ error: "productboard_api_error" });
  }
});

// ---------- Disconnect ----------
app.post("/productboard/disconnect", async (req, res) => {
  const uid = req.query.zoho_user_id;
  if (!uid) return res.status(400).json({ error: "missing zoho_user_id" });
  await db.run("DELETE FROM tokens WHERE zoho_user_id = ?", uid);
  return res.json({ ok:true });
});

// ---------- start ----------
app.listen(PORT, () => {
  console.log(`Proxy running on ${PORT}, redirect_uri=${REDIRECT_URI}`);
});
