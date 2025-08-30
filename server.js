import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import crypto from "crypto";
import qs from "qs";

dotenv.config();
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ================= In-memory tokens (demo) ================= */
const shopTokens = new Map();

/* ================= Helpers ================= */
const isValidShop = (shop) =>
  typeof shop === "string" && /^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/.test(shop);

/** Verify OAuth callback HMAC */
function verifyCallbackHmac(query, secret) {
  const { hmac, ...rest } = query;
  const message = qs.stringify(rest, { encode: false });
  const digest = crypto.createHmac("sha256", secret).update(message).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

/** ✅ Verify App Proxy signature using the RAW query string (no reordering, no decoding) */
function verifyAppProxySignature(req, secret) {
  const originalUrl = req.originalUrl || "";
  const qIndex = originalUrl.indexOf("?");
  if (qIndex === -1) return false;

  const rawQS = originalUrl.slice(qIndex + 1);

  // Βγάλε ΜΟΝΟ το signature=..., κράτα την αρχική σειρά/encoding των λοιπών παραμέτρων
  const parts = rawQS.split("&");
  let provided = null;
  const filtered = [];

  for (const p of parts) {
    if (p.startsWith("signature=")) {
      provided = p.slice("signature=".length);
    } else {
      filtered.push(p);
    }
  }

  if (!provided) return false;

  const message = filtered.join("&"); // raw, same order
  const expected = crypto.createHmac("sha256", secret).update(message).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
  } catch {
    return false;
  }
}

/* ================= Routes ================= */

/** Health */
app.get("/health", (req, res) => {
  res.status(200).send("ok");
});

/** 1) OAuth begin */
app.get("/auth", (req, res) => {
  const shop = (req.query.shop || "").toString();
  if (!isValidShop(shop)) return res.status(400).send("Missing/invalid shop param");

  const state = crypto.randomBytes(16).toString("hex");
  const redirectUri = `${process.env.HOST}/auth/callback`;
  const scopes = process.env.SCOPES;

  console.log("⚡️ AUTH request:");
  console.log("- shop:", shop);
  console.log("- client_id (SHOPIFY_API_KEY):", (process.env.SHOPIFY_API_KEY || "").slice(0, 6) + "...");
  console.log("- redirectUri:", redirectUri);
  console.log("- scopes:", scopes);

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(process.env.SHOPIFY_API_KEY)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  res.redirect(installUrl);
});

/** 2) OAuth callback */
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code, hmac } = req.query;
    if (!isValidShop(shop) || !code || !hmac) return res.status(400).send("Missing params");

    if (!verifyCallbackHmac(req.query, process.env.SHOPIFY_API_SECRET)) {
      console.error("❌ OAuth HMAC verification failed");
      return res.status(401).send("Invalid HMAC");
    }

    const tokenUrl = `https://${shop}/admin/oauth/access_token`;
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: process.env.SHOPIFY_API_KEY,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error("❌ Token exchange failed:", text);
      return res.status(500).send("Token exchange failed");
    }

    const data = await response.json();
    const accessToken = data.access_token;
    shopTokens.set(shop, accessToken);
    console.log("✅ ACCESS TOKEN (masked):", (accessToken || "").slice(0, 6), "...");

    res.redirect(`/health?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    console.error("Auth callback error:", err);
    res.status(500).send("Auth callback error");
  }
});

/** 3) App Proxy health (GET) */
app.get("/proxy/health", (req, res) => {
  const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
  if (!ok) {
    console.warn("Proxy HMAC fail:", req.originalUrl);
    return res.status(401).json({ ok: false, error: "Invalid proxy signature" });
  }
  res.json({ ok: true, route: "proxy/health" });
});

/** 4) App Proxy example (POST) */
app.post("/proxy/update-customer", (req, res) => {
  const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
  if (!ok) {
    console.warn("Proxy HMAC fail (POST):", req.originalUrl);
    return res.status(401).json({ ok: false, error: "Invalid proxy signature" });
  }
  res.json({ ok: true, received: req.body });
});

/** (Optional) Debug: check token presence */
app.get("/debug/has-token", (req, res) => {
  const shop = (req.query.shop || "").toString();
  res.json({ shop, hasToken: !!shopTokens.get(shop) });
});

/* ================= Start ================= */
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log("HOST:", process.env.HOST);
});
