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

/**
 * Verify App Proxy Signature
 * Shopify signs: path + sorted query params (without signature)
 */
function verifyAppProxySignature(req, secret) {
  const { signature, ...otherParams } = req.query;
  
  if (!signature) {
    console.log("❌ No signature provided");
    return false;
  }

  // Sort parameters alphabetically by key
  const sortedParams = Object.keys(otherParams)
    .sort()
    .map(key => {
      const value = Array.isArray(otherParams[key]) 
        ? otherParams[key].join(',') 
        : otherParams[key];
      return `${key}=${value}`;
    })
    .join('');

  console.log("🔍 Verifying App Proxy signature:");
  console.log("- Sorted params string:", sortedParams);
  console.log("- Provided signature:", signature);

  const calculated = crypto
    .createHmac("sha256", secret)
    .update(sortedParams)
    .digest("hex");
  
  console.log("- Calculated signature:", calculated);

  try {
    return crypto.timingSafeEqual(
      Buffer.from(calculated, 'hex'),
      Buffer.from(signature, 'hex')
    );
  } catch (err) {
    console.error("❌ Signature comparison error:", err);
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
  console.log("📍 Proxy health check");
  console.log("- Path:", req.path);
  console.log("- Query params:", req.query);
  
  const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
  
  if (!ok) {
    console.warn("❌ Proxy signature verification failed");
    return res.status(401).json({ 
      ok: false, 
      error: "Invalid proxy signature",
      debug: {
        path: req.path,
        query: req.query
      }
    });
  }
  
  console.log("✅ Proxy signature verified successfully");
  res.json({ 
    ok: true, 
    route: "proxy/health",
    timestamp: new Date().toISOString(),
    shop: req.query.shop || "unknown"
  });
});

/** 4) App Proxy example (POST) */
app.post("/proxy/update-customer", (req, res) => {
  console.log("📍 Proxy update-customer");
  console.log("- Path:", req.path);
  console.log("- Query params:", req.query);
  console.log("- Body:", req.body);
  
  const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
  
  if (!ok) {
    console.warn("❌ Proxy signature verification failed (POST)");
    return res.status(401).json({ 
      ok: false, 
      error: "Invalid proxy signature" 
    });
  }
  
  console.log("✅ Proxy signature verified successfully (POST)");
  res.json({ 
    ok: true, 
    received: req.body,
    shop: req.query.shop || "unknown"
  });
});

/** 5) Debug endpoint για να δούμε τι στέλνει το Shopify */
app.all("/proxy/*", (req, res) => {
  console.log("🔍 DEBUG - Catch-all proxy route");
  console.log("- Method:", req.method);
  console.log("- Path:", req.path);
  console.log("- Original URL:", req.originalUrl);
  console.log("- Query:", req.query);
  console.log("- Headers:", req.headers);
  
  // Προσπάθησε να επαληθεύσεις την υπογραφή
  const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
  
  res.json({
    ok,
    debug: {
      method: req.method,
      path: req.path,
      query: req.query,
      signature_valid: ok
    }
  });
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
