// server.js
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

const mask = (val = "", visible = 6) =>
  typeof val === "string" && val.length > visible ? `${val.slice(0, visible)}...` : val;

/** Verify OAuth callback HMAC (Shopify OAuth) */
function verifyCallbackHmac(query, secret) {
  const { hmac, ...rest } = query;
  const message = qs.stringify(rest, { encode: false });
  const digest = crypto.createHmac("sha256", secret).update(message).digest("hex");
  try {
    const a = Buffer.from(digest, "utf8");
    const b = Buffer.from(hmac, "utf8");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Verify App Proxy Signature
 * Shopify στέλνει ?signature=<hex>. Υπογράφουμε την αλφαβητικά ταξινομημένη query-string (χωρίς το 'signature').
 * (Σημ.: Αυτή η υλοποίηση είναι συμβατή με το working endpoint σου.)
 */
function verifyAppProxySignature(req, secret) {
  const { signature, ...otherParams } = req.query || {};
  if (!signature) return false;

  const sortedParams = Object.keys(otherParams)
    .sort()
    .map((key) => {
      const value = Array.isArray(otherParams[key]) ? otherParams[key].join(",") : otherParams[key];
      return `${key}=${value}`;
    })
    .join("");

  const calculated = crypto.createHmac("sha256", secret).update(sortedParams).digest("hex");

  try {
    const a = Buffer.from(calculated, "hex");
    const b = Buffer.from(signature, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/* ================= Routes ================= */

/** Health */
app.get("/health", (_req, res) => {
  res.status(200).send("ok");
});

/** 1) OAuth begin */
app.get("/auth", (req, res) => {
  const shop = (req.query.shop || "").toString();
  if (!isValidShop(shop)) return res.status(400).send("Missing/invalid shop param");

  const state = crypto.randomBytes(16).toString("hex");
  const redirectUri = `${process.env.HOST}/auth/callback`;
  const scopes = process.env.SCOPES || "";

  const url = new URL(`https://${shop}/admin/oauth/authorize`);
  url.searchParams.set("client_id", process.env.SHOPIFY_API_KEY);
  url.searchParams.set("scope", scopes);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);

  console.log("⚡️ AUTH request:", { shop, client_id: mask(process.env.SHOPIFY_API_KEY), redirectUri, scopes });
  res.redirect(url.toString());
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

    const text = await response.text();
    if (!response.ok) {
      console.error("❌ Token exchange failed:", text);
      return res.status(500).send("Token exchange failed");
    }

    const data = JSON.parse(text);
    const accessToken = data.access_token;
    shopTokens.set(shop, accessToken);
    console.log("✅ Access token stored for", shop, mask(accessToken));

    res.redirect(`/health?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    console.error("Auth callback error:", err);
    res.status(500).send("Auth callback error");
  }
});

/** 3) App Proxy health (GET) */
app.get("/proxy/health", (req, res) => {
  const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
  if (!ok) return res.status(401).json({ ok: false, error: "Invalid proxy signature" });

  res.json({
    ok: true,
    route: "proxy/health",
    timestamp: new Date().toISOString(),
    shop: req.query.shop || "unknown",
  });
});

/** 4) App Proxy example (POST) */
app.post("/proxy/update-customer", (req, res) => {
  const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
  if (!ok) return res.status(401).json({ ok: false, error: "Invalid proxy signature" });

  res.json({
    ok: true,
    received: req.body,
    shop: req.query.shop || "unknown",
  });
});

/** 5) Admin API route για δημιουργία Metafield σε Customer */
app.post("/api/customers/:id/metafields", async (req, res) => {
  try {
    const shop = (req.query.shop || "").toString();
    const token = shopTokens.get(shop);
    if (!shop || !token) return res.status(401).json({ ok: false, error: "No token for shop" });

    const { key, value, namespace = "nobelle", type = "single_line_text_field" } = req.body || {};
    const customerId = req.params.id;

    if (!key || typeof value === "undefined") {
      return res.status(400).json({ ok: false, error: "Missing key/value" });
    }

    const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-07";
    const endpoint = `https://${shop}/admin/api/${apiVersion}/customers/${customerId}/metafields.json`;

    const resp = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": token,
      },
      body: JSON.stringify({
        metafield: { namespace, key, type, value },
      }),
    });

    const data = await resp.json();
    if (!resp.ok) {
      console.error("❌ Admin API error:", data);
      return res.status(resp.status).json({ ok: false, error: data });
    }

    res.json({ ok: true, metafield: data.metafield });
  } catch (e) {
    console.error("❌ Admin API exception:", e);
    res.status(500).json({ ok: false, error: "Admin API error" });
  }
});

/** (Optional) Debug: check token presence */
app.get("/debug/has-token", (req, res) => {
  const shop = (req.query.shop || "").toString();
  res.json({ shop, hasToken: !!shopTokens.get(shop) });
});

/* ================= Start ================= */
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log("🌐 HOST:", process.env.HOST);
  console.log("🔑 API Key configured:", !!process.env.SHOPIFY_API_KEY);
  console.log("🔐 API Secret configured:", !!process.env.SHOPIFY_API_SECRET);
});
