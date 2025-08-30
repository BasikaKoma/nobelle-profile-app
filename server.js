import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import qs from "qs";

dotenv.config();
const app = express();

app.use(express.json());

/**
 * Health check
 */
app.get("/health", (req, res) => res.send("ok"));

/**
 * 1. Start OAuth
 */
app.get("/auth", (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send("Missing shop param");

  const redirectUri = `${process.env.HOST}/auth/callback`;
  const scopes = process.env.SCOPES;

  console.log("⚡️ AUTH request:");
  console.log("- shop:", shop);
  console.log("- client_id (SHOPIFY_API_KEY):", process.env.SHOPIFY_API_KEY?.slice(0, 6) + "..."); // δείχνει μόνο τα πρώτα 6 chars για έλεγχο
  console.log("- redirectUri:", redirectUri);
  console.log("- scopes:", scopes);

  const installUrl =
    `https://${shop}/admin/oauth/authorize?` +
    `client_id=${process.env.SHOPIFY_API_KEY}` +
    `&scope=${scopes}` +
    `&redirect_uri=${redirectUri}`;

  res.redirect(installUrl);
});


/**
 * 2. OAuth Callback
 */
app.get("/auth/callback", async (req, res) => {
  const { shop, code } = req.query;
  if (!shop || !code) return res.status(400).send("Missing params");

  // Exchange temporary code for a permanent token
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

  const data = await response.json();
  console.log("ACCESS TOKEN:", data.access_token);

  // ⚠️ Για production αποθήκευσε το token σε DB. Τώρα απλά το δείχνουμε.
  res.send("App installed. You can close this window.");
});

/**
 * Proxy route example
 */
app.post("/proxy/update-customer", (req, res) => {
  res.json({ ok: true, received: req.body });
});

/**
 * Start server
 */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
