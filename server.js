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
  try {
    return crypto.timingSafeEqual(Buffer.from(digest, "hex"), Buffer.from(hmac, "hex"));
  } catch {
    return false;
  }
}

/**
 * Verify App Proxy Signature
 * Shopify υπογράφει: path + sorted query params (ΧΩΡΙΣ το signature)
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

  const path = req.path || ""; // π.χ. "/proxy/save-customer-metafields"
  const toSign = `${path}${sortedParams}`;
  const calculated = crypto.createHmac("sha256", secret).update(toSign).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(calculated, "hex"), Buffer.from(signature, "hex"));
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

  console.log("⚡️ AUTH request for shop:", shop);
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
    console.log("✅ Access token stored for", shop);

    res.send(`
      <html>
        <body>
          <h1>✅ App installed successfully!</h1>
          <p>You can now close this window and use the app.</p>
          <script>
            setTimeout(() => {
              window.location.href = 'https://${shop}/admin/apps';
            }, 3000);
          </script>
        </body>
      </html>
    `);
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

/** 4) App Proxy: prefill customer metafields (GET) */
app.get("/proxy/get-customer-metafields", async (req, res) => {
  try {
    if (!verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET)) {
      return res.status(401).json({ ok: false, error: "Invalid proxy signature" });
    }

    const shop = (req.query.shop || "").toString();
    const customerId = (req.query.logged_in_customer_id || "").toString(); // από App Proxy
    if (!shop || !customerId) return res.status(400).json({ ok: false, error: "Missing shop/customerId" });

    const token = shopTokens.get(shop);
    if (!token) return res.status(401).json({ ok: false, error: "No token for shop" });

    const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-07";
    const base = `https://${shop}/admin/api/${apiVersion}`;

    const r = await fetch(`${base}/customers/${customerId}/metafields.json?namespace=nobelle`, {
      headers: { "X-Shopify-Access-Token": token },
    });
    const data = await r.json();

    // Κάνε map σε key:value για ευκολία στο UI
    const out = {};
    (data.metafields || []).forEach((m) => {
      out[m.key] = m.value;
    });

    return res.json({ ok: true, customerId, namespace: "nobelle", metafields: out, raw: data.metafields || [] });
  } catch (e) {
    console.error("prefill error", e);
    return res.status(500).json({ ok: false, error: "prefill_failed" });
  }
});

/** 5) App Proxy: save customer metafields (POST) */
app.post("/proxy/save-customer-metafields", async (req, res) => {
  try {
    // 1) Verify Proxy signature
    const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
    if (!ok) return res.status(401).json({ ok: false, error: "Invalid proxy signature" });

    // 2) Get shop & token
    const shop = (req.query.shop || "").toString();
    const token = shopTokens.get(shop);
    if (!shop || !token) {
      console.log("❌ No token for shop:", shop);
      return res.status(401).json({ ok: false, error: "No token for shop. Please reinstall the app." });
    }

    // 3) Get data from UI
    const { customerId, company_name, vat_number, phone, profile_note, birthday, preferences } = req.body || {};
    if (!customerId) return res.status(400).json({ ok: false, error: "Missing customerId" });

    console.log("📝 Saving metafields for customer:", customerId);

    const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-07";
    const base = `https://${shop}/admin/api/${apiVersion}`;

    // 4) Build metafields to write
    const metafieldsToWrite = [];
    if (company_name != null && company_name !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "company_name", type: "single_line_text_field", value: String(company_name) });
    if (vat_number != null && vat_number !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "vat_number", type: "single_line_text_field", value: String(vat_number) });
    if (phone != null && phone !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "phone", type: "single_line_text_field", value: String(phone) });
    if (profile_note != null && profile_note !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "profile_note", type: "multi_line_text_field", value: String(profile_note) });
    if (birthday != null && birthday !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "birthday", type: "date", value: String(birthday) }); // YYYY-MM-DD
    if (preferences != null)
      metafieldsToWrite.push({ namespace: "nobelle", key: "preferences", type: "json", value: JSON.stringify(preferences) });

    if (!metafieldsToWrite.length)
      return res.status(400).json({ ok: false, error: "No fields provided" });

    // 5) Create/update metafields one by one (REST)
    const results = [];
    const errors = [];

    for (const mf of metafieldsToWrite) {
      try {
        const resp = await fetch(`${base}/customers/${customerId}/metafields.json`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": token,
          },
          body: JSON.stringify({ metafield: mf }),
        });

        const data = await resp.json();

        if (!resp.ok) {
          // Try to update if it exists
          const msg = JSON.stringify(data);
          const alreadyTaken =
            (data?.errors?.metafield && String(data.errors.metafield).includes("has already been taken")) ||
            msg.includes("has already been taken");

          if (alreadyTaken) {
            const searchResp = await fetch(
              `${base}/customers/${customerId}/metafields.json?namespace=${mf.namespace}&key=${mf.key}`,
              { headers: { "X-Shopify-Access-Token": token } }
            );
            const searchData = await searchResp.json();

            if (searchData.metafields && searchData.metafields.length > 0) {
              const existingId = searchData.metafields[0].id;
              const updateResp = await fetch(`${base}/metafields/${existingId}.json`, {
                method: "PUT",
                headers: {
                  "Content-Type": "application/json",
                  "X-Shopify-Access-Token": token,
                },
                body: JSON.stringify({ metafield: { id: existingId, value: mf.value } }),
              });
              const updateData = await updateResp.json();
              if (updateResp.ok) {
                results.push(updateData.metafield);
              } else {
                errors.push({ field: mf.key, error: updateData });
              }
            } else {
              errors.push({ field: mf.key, error: "Existing metafield not found for update" });
            }
          } else {
            errors.push({ field: mf.key, error: data });
          }
        } else {
          results.push(data.metafield);
        }
      } catch (e) {
        errors.push({ field: mf.key, error: e.message });
      }
    }

    if (errors.length > 0) {
      console.error("⚠️ Some metafields had errors:", errors);
    }

    return res.json({
      ok: true,
      saved: results,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (e) {
    console.error("❌ save-customer-metafields error:", e);
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

/** 6) Debug: check token presence */
app.get("/debug/has-token", (req, res) => {
  const shop = (req.query.shop || "").toString();
  res.json({ shop, hasToken: !!shopTokens.get(shop) });
});

/** 7) Debug: list all shops with tokens */
app.get("/debug/shops", (_req, res) => {
  const shops = Array.from(shopTokens.keys());
  res.json({ shops, count: shops.length });
});

/* ================= Start ================= */
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log(`🌐 HOST: ${process.env.HOST}`);
  console.log(`🔑 API Key: ${process.env.SHOPIFY_API_KEY ? "✅ Configured" : "❌ Missing"}`);
  console.log(`🔐 API Secret: ${process.env.SHOPIFY_API_SECRET ? "✅ Configured" : "❌ Missing"}`);
});
