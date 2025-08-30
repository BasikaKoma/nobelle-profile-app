import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
@@ -18,28 +17,20 @@ const shopTokens = new Map();
const isValidShop = (shop) =>
  typeof shop === "string" && /^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/.test(shop);

const mask = (val = "", visible = 6) =>
  typeof val === "string" && val.length > visible ? `${val.slice(0, visible)}...` : val;

/** Verify OAuth callback HMAC (Shopify OAuth) */
/** Verify OAuth callback HMAC */
function verifyCallbackHmac(query, secret) {
  const { hmac, ...rest } = query;
  const message = qs.stringify(rest, { encode: false });
  const digest = crypto.createHmac("sha256", secret).update(message).digest("hex");
  try {
    const a = Buffer.from(digest, "utf8");
    const b = Buffer.from(hmac, "utf8");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
    return crypto.timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(hmac, 'hex'));
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
@@ -56,10 +47,7 @@ function verifyAppProxySignature(req, secret) {
  const calculated = crypto.createHmac("sha256", secret).update(sortedParams).digest("hex");

  try {
    const a = Buffer.from(calculated, "hex");
    const b = Buffer.from(signature, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
    return crypto.timingSafeEqual(Buffer.from(calculated, "hex"), Buffer.from(signature, "hex"));
  } catch {
    return false;
  }
@@ -87,7 +75,7 @@ app.get("/auth", (req, res) => {
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);

  console.log("⚡️ AUTH request:", { shop, client_id: mask(process.env.SHOPIFY_API_KEY), redirectUri, scopes });
  console.log("⚡️ AUTH request for shop:", shop);
  res.redirect(url.toString());
});

@@ -122,9 +110,22 @@ app.get("/auth/callback", async (req, res) => {
    const data = JSON.parse(text);
    const accessToken = data.access_token;
    shopTokens.set(shop, accessToken);
    console.log("✅ Access token stored for", shop, mask(accessToken));

    res.redirect(`/health?shop=${encodeURIComponent(shop)}`);
    console.log("✅ Access token stored for", shop);

    // Redirect to success page
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
@@ -144,70 +145,132 @@ app.get("/proxy/health", (req, res) => {
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
/** 4) App Proxy: save customer metafields (POST) */
app.post("/proxy/save-customer-metafields", async (req, res) => {
  try {
    // 1) Verify Proxy signature
    const ok = verifyAppProxySignature(req, process.env.SHOPIFY_API_SECRET);
    if (!ok) return res.status(401).json({ ok: false, error: "Invalid proxy signature" });

    // 2) Get shop & token
    const shop = (req.query.shop || "").toString();
    const token = shopTokens.get(shop);
    if (!shop || !token) return res.status(401).json({ ok: false, error: "No token for shop" });
    if (!shop || !token) {
      console.log("❌ No token for shop:", shop);
      return res.status(401).json({ ok: false, error: "No token for shop. Please reinstall the app." });
    }

    const { key, value, namespace = "nobelle", type = "single_line_text_field" } = req.body || {};
    const customerId = req.params.id;
    // 3) Get data from UI
    const { customerId, company_name, vat_number, phone, profile_note } = req.body || {};
    if (!customerId) return res.status(400).json({ ok: false, error: "Missing customerId" });

    if (!key || typeof value === "undefined") {
      return res.status(400).json({ ok: false, error: "Missing key/value" });
    }
    console.log("📝 Saving metafields for customer:", customerId);

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
    const base = `https://${shop}/admin/api/${apiVersion}`;
    
    // 4) Build metafields to write
    const metafieldsToWrite = [];
    if (company_name !== undefined && company_name !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "company_name", type: "single_line_text_field", value: String(company_name) });
    if (vat_number !== undefined && vat_number !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "vat_number", type: "single_line_text_field", value: String(vat_number) });
    if (phone !== undefined && phone !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "phone", type: "single_line_text_field", value: String(phone) });
    if (profile_note !== undefined && profile_note !== "")
      metafieldsToWrite.push({ namespace: "nobelle", key: "profile_note", type: "multi_line_text_field", value: String(profile_note) });

    if (!metafieldsToWrite.length)
      return res.status(400).json({ ok: false, error: "No fields provided" });

    // 5) Create/update metafields one by one
    const results = [];
    const errors = [];
    
    for (const mf of metafieldsToWrite) {
      try {
        const resp = await fetch(`${base}/customers/${customerId}/metafields.json`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": token
          },
          body: JSON.stringify({ metafield: mf })
        });
        
        const data = await resp.json();
        
        if (!resp.ok) {
          // Try to update if it exists
          if (data.errors && data.errors.metafield && data.errors.metafield.includes("has already been taken")) {
            // Get existing metafield
            const searchResp = await fetch(`${base}/customers/${customerId}/metafields.json?namespace=${mf.namespace}&key=${mf.key}`, {
              headers: { "X-Shopify-Access-Token": token }
            });
            const searchData = await searchResp.json();
            
            if (searchData.metafields && searchData.metafields.length > 0) {
              const existingId = searchData.metafields[0].id;
              // Update it
              const updateResp = await fetch(`${base}/metafields/${existingId}.json`, {
                method: "PUT",
                headers: {
                  "Content-Type": "application/json",
                  "X-Shopify-Access-Token": token
                },
                body: JSON.stringify({ metafield: { id: existingId, value: mf.value } })
              });
              const updateData = await updateResp.json();
              if (updateResp.ok) {
                results.push(updateData.metafield);
              } else {
                errors.push({ field: mf.key, error: updateData });
              }
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

    const data = await resp.json();
    if (!resp.ok) {
      console.error("❌ Admin API error:", data);
      return res.status(resp.status).json({ ok: false, error: data });
    if (errors.length > 0) {
      console.error("⚠️ Some metafields had errors:", errors);
    }

    res.json({ ok: true, metafield: data.metafield });
    return res.json({ 
      ok: true, 
      saved: results,
      errors: errors.length > 0 ? errors : undefined
    });
    
  } catch (e) {
    console.error("❌ Admin API exception:", e);
    res.status(500).json({ ok: false, error: "Admin API error" });
    console.error("❌ save-customer-metafields error:", e);
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

/** (Optional) Debug: check token presence */
/** 5) Debug: check token presence */
app.get("/debug/has-token", (req, res) => {
  const shop = (req.query.shop || "").toString();
  res.json({ shop, hasToken: !!shopTokens.get(shop) });
});

/** 6) Debug: list all shops with tokens */
app.get("/debug/shops", (_req, res) => {
  const shops = Array.from(shopTokens.keys());
  res.json({ shops, count: shops.length });
});

/* ================= Start ================= */
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log("🌐 HOST:", process.env.HOST);
  console.log("🔑 API Key configured:", !!process.env.SHOPIFY_API_KEY);
  console.log("🔐 API Secret configured:", !!process.env.SHOPIFY_API_SECRET);
  console.log(`🌐 HOST: ${process.env.HOST}`);
  console.log(`🔑 API Key: ${process.env.SHOPIFY_API_KEY ? '✅ Configured' : '❌ Missing'}`);
  console.log(`🔐 API Secret: ${process.env.SHOPIFY_API_SECRET ? '✅ Configured' : '❌ Missing'}`);
