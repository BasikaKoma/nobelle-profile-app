import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import crypto from "crypto";
import qs from "qs";

dotenv.config();
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * In-memory αποθήκευση token για δοκιμές.
 * (Σε production βάλ’ το σε DB/kv.)
 */
const shopTokens = new Map();

/* ------------------------ Helpers ------------------------ */

/** Απλό check για έγκυρο myshopify domain */
const isValidShop = (shop) =>
  typeof shop === "string" && /^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/.test(shop);

/** Verify HMAC (OAuth callback) */
function verifyCallbackHmac(query, secret) {
  const { hmac, ...rest } = query;
  const message = qs.stringify(rest, { encode: false });
  const digest = crypto.createHmac("sha256", secret).update(message).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

function verifyAppProxySignature(req, secret) {
  // Παίρνουμε το raw query string όπως ήρθε (χωρίς reorder/encode changes)
  const originalUrl = req.originalUrl || "";
  const qIndex = originalUrl.indexOf("?");
  if (qIndex === -1) return false;

  const rawQS = originalUrl.slice(qIndex + 1); // ό,τι υπάρχει μετά το '?'
  // βγάζουμε ΜΟΝΟ το signature=... αλλά κρατάμε την ίδια σειρά & encoding
  const parts = rawQS.split("&").filter(p => !p.startsWith("signature="));
  const message = parts.join("&");

  // Εξάγουμε το signature από το raw query (χωρίς να αλλάξουμε σειρά/encoding)
  const sigMatch = rawQS.match(/(?:^|&)signature=([0-9a-fA-F]+)/);
  const provided = sigMatch ? sigMatch[1] : null;
  if (!provided) return false;

  const expected = crypto.createHmac("sha256", secret).update(message).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
  } catch {
    return false;
  }
}


/* ------------------------ Routes ------------------------ */

/** Health */
app.get("/health", (req, res) => {
  // Αν θέλεις auto-OAuth όταν δεν υπάρχει token, ξεκλείδωσε τα παρακάτω 2 lines:
  // const shop = (req.query.shop || "").toString();
  // if (isValidShop(shop) && !shopTokens.get(shop)) return res.redirect(`/auth?shop=${encodeURIComponent(shop)}`);
  res.status(200).send("ok");
});

/** 1) OAuth begin */
app.get("/auth", (req, res) => {
  const shop = (req.query.shop || "").toString();
  if (!isValidShop(shop)) return res.status(400).send("Missing/invalid shop param");

  const state = crypto.randomBytes(16).toString("hex"); // μπορείς να το σώσεις σε cookie/session για CSRF
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

    if (!isValidShop(shop) || !code || !hmac) {
      return res.status(400).send("Missing params");
    }

    // HMAC verification (ασφάλεια)
    const ok = verifyCallbackHmac(req.query, process.env.SHOPIFY_API_SECRET);
    if (!ok) {
      console.error("❌ HMAC verification failed");
      return res.status(401).send("Invalid HMAC");
    }

    // Exchange code → access token
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

    // Επιστροφή στο app UI (βάζω health για απλότητα)
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
  res.json({ ok: true, route: "proxy/health" });
});

/** 4) App Proxy example (POST) */
app.post("/proxy/update-customer", (req, res) => {
  const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
  if (!ok) return res.status(401).json({ ok: false, error: "Invalid proxy signature" });

  // εδώ θα καλέσεις Admin API με το token του συγκεκριμένου shop
  // const shop = req.query.shop; const token = shopTokens.get(shop);
  res.json({ ok: true, received: req.body });
});

/* ------------------------ Start server ------------------------ */

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log("HOST:", process.env.HOST);
});
