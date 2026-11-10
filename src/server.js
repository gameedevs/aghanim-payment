require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const crypto = require("crypto");
const { MongoClient } = require("mongodb");

const app = express();
app.disable("x-powered-by");
app.use(helmet());

let mongoClient;
let db;

async function connectMongo() {
  if (db) return db;
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is required");

  mongoClient = new MongoClient(process.env.MONGODB_URI, {
    maxPoolSize: Number(process.env.MONGODB_MAX_POOL_SIZE || 10),
    serverSelectionTimeoutMS: 10000
  });
  await mongoClient.connect();
  db = mongoClient.db(process.env.MONGODB_DATABASE || "aghanim_payment");

  await db.collection("webhook_events").createIndex(
    { receivedAt: 1 }, { expireAfterSeconds: 15552000, name: "ttl_180d" }
  );
  await db.collection("payment_orders").createIndex(
    { playerId: 1, updatedAt: -1 }, { name: "player_updated" }
  );
  console.log("MongoDB connected");
  return db;
}

function verifySignature(rawBody, timestamp, received, secret) {
  if (!Buffer.isBuffer(rawBody) || !timestamp || !received || !secret) return false;
  const signed = Buffer.concat([Buffer.from(`${timestamp}.`), rawBody]);
  const expected = crypto.createHmac("sha256", secret).update(signed).digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(String(received).toLowerCase(), "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function mapOrderStatus(event) {
  const status = String(event?.context?.order?.status || "").toLowerCase();
  const trigger = String(event?.trigger || "").toLowerCase();
  if (status === "paid" || trigger === "order.paid") return "PAID";
  if (status === "refunded" || status === "refund_requested" ||
      trigger === "order.refunded" || trigger === "checkout.refund") return "REFUNDED";
  if (status === "canceled" || trigger === "order.canceled" ||
      trigger === "checkout.cancel") return "CANCELED";
  return null;
}

async function processWebhook(event) {
  const eventKey = event.idempotency_key || event.event_id;
  if (!eventKey) {
    const e = new Error("Missing idempotency_key and event_id");
    e.statusCode = 400;
    throw e;
  }

  const type = event.event_type;
  const data = event.event_data || {};
  const orderId = event.context?.order?.id || null;
  const playerId = data.player_id || null;
  const status = mapOrderStatus(event);
  const database = db;
  const session = mongoClient.startSession();

  try {
    await session.withTransaction(async () => {
      await database.collection("webhook_events").insertOne({
        _id: String(eventKey),
        eventId: event.event_id || null,
        eventType: type || null,
        trigger: event.trigger || null,
        orderId,
        playerId,
        sandbox: Boolean(event.sandbox),
        receivedAt: new Date()
      }, { session });

      // Aghanim Checkout purchase: item.add + trigger=order.paid.
      if (type === "item.add" && event.trigger === "order.paid") {
        if (!orderId || !playerId || status !== "PAID") {
          const e = new Error("Paid item.add missing order/player/paid status");
          e.statusCode = 422;
          throw e;
        }
        await database.collection("payment_orders").updateOne(
          { _id: orderId },
          {
            $set: {
              orderId, playerId, status: "PAID",
              items: Array.isArray(data.items) ? data.items : [],
              sandbox: Boolean(event.sandbox),
              transactionId: event.transaction_id || null,
              receiptNumber: event.context?.order?.receipt_number || null,
              paidAt: event.context?.order?.paid_at
                ? new Date(Number(event.context.order.paid_at) * 1000) : new Date(),
              updatedAt: new Date()
            },
            $setOnInsert: { createdAt: new Date(), claimed: false, claimedAt: null }
          },
          { upsert: true, session }
        );
      }

      const removalTrigger = String(event.trigger || "").toLowerCase();
      const isOrderRemoval =
        ["order.refunded", "order.canceled", "checkout.refund", "checkout.cancel"].includes(removalTrigger) ||
        ["refunded", "refund_requested", "canceled"].includes(
          String(event.context?.order?.status || "").toLowerCase()
        );

      if (type === "item.remove" && isOrderRemoval) {
        if (!orderId || !playerId || !["REFUNDED", "CANCELED"].includes(status)) {
          const e = new Error("Order item.remove missing order/player/refund status");
          e.statusCode = 422;
          throw e;
        }
        await database.collection("payment_orders").updateOne(
          { _id: orderId },
          {
            $set: {
              orderId, playerId, status,
              removedItems: Array.isArray(data.items) ? data.items : [],
              sandbox: Boolean(event.sandbox),
              transactionId: event.transaction_id || null,
              updatedAt: new Date()
            },
            $setOnInsert: { createdAt: new Date() }
          },
          { upsert: true, session }
        );
      }
    });
    return { duplicate: false, orderId, type, status };
  } catch (e) {
    if (e.code === 11000) return { duplicate: true, orderId, type, status };
    throw e;
  } finally {
    await session.endSession();
  }
}

// Keep this route BEFORE express.json(): Aghanim signature is over raw request bytes.
app.post("/webhook/aghanim", express.raw({ type: "*/*", limit: "1mb" }), async (req, res) => {
  try {
    const secret = process.env.AGHANIM_WEBHOOK_SECRET;
    if (!verifySignature(
      req.body,
      req.get("X-Aghanim-Signature-Timestamp"),
      req.get("X-Aghanim-Signature"),
      secret
    )) return res.status(401).json({ error: "Invalid webhook signature" });

    let event;
    try { event = JSON.parse(req.body.toString("utf8")); }
    catch { return res.status(400).json({ error: "Invalid JSON" }); }

    if (process.env.AGHANIM_GAME_ID && event.game_id !== process.env.AGHANIM_GAME_ID) {
      return res.status(403).json({ error: "Unexpected game_id" });
    }

    const result = await processWebhook(event);
    if (process.env.LOG_WEBHOOK_METADATA === "true") {
      console.log("Webhook processed", {
        type: result.type, orderId: result.orderId,
        status: result.status, duplicate: result.duplicate,
        sandbox: Boolean(event.sandbox)
      });
    }
    return res.status(200).json({ status: "ok", duplicate: result.duplicate });
  } catch (e) {
    console.error("Webhook error:", e.message);
    return res.status(e.statusCode || 500).json({
      error: e.statusCode ? e.message : "Webhook processing failed"
    });
  }
});

app.use(express.json({ limit: "100kb" }));

app.get("/health", async (_req, res) => {
  try {
    await db.command({ ping: 1 });
    return res.json({ status: "ok", database: "connected" });
  } catch {
    return res.status(503).json({ status: "error", database: "disconnected" });
  }
});

// Paid orders the player has not been rewarded for yet (direct checkout and Hub alike).
app.get("/api/payment/unclaimed", async (req, res) => {
  try {
    const playerId = String(req.query.playerId || "").trim();
    if (!playerId || playerId.length > 128) {
      return res.status(400).json({ error: "playerId is required" });
    }

    const orders = await db.collection("payment_orders")
      .find({ playerId, status: "PAID", claimed: { $ne: true } })
      .sort({ paidAt: 1 })
      .limit(20)
      .toArray();

    console.log("Unclaimed check", {
      player: playerId.slice(0, 8),
      count: orders.length,
      orderIds: orders.map((o) => o.orderId)
    });

    return res.json({
      orders: orders.map((o) => ({
        orderId: o.orderId,
        items: o.items || [],
        sandbox: Boolean(o.sandbox),
        paidAt: o.paidAt || null
      }))
    });
  } catch (e) {
    console.error("Unclaimed orders error:", e.message);
    return res.status(500).json({ error: "Could not retrieve orders" });
  }
});

// Called by the client AFTER it granted the reward. Idempotent: repeating it is safe.
app.post("/api/payment/claim/:orderId", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim();
    const playerId = String(req.body?.playerId || "").trim();
    if (!orderId || !playerId) {
      return res.status(400).json({ error: "orderId and playerId are required" });
    }

    const orders = db.collection("payment_orders");
    const updated = await orders.findOneAndUpdate(
      { _id: orderId, playerId, status: "PAID", claimed: { $ne: true } },
      { $set: { claimed: true, claimedAt: new Date(), updatedAt: new Date() } }
    );
    if (updated) {
      console.log("Claim ok", { orderId, player: playerId.slice(0, 8) });
      return res.json({ orderId, claimed: true });
    }

    const order = await orders.findOne({ _id: orderId });
    if (!order || order.playerId !== playerId) {
      console.log("Claim not found", { orderId, player: playerId.slice(0, 8) });
      return res.status(404).json({ error: "Order not found" });
    }
    if (order.claimed === true) {
      console.log("Claim already claimed", { orderId, player: playerId.slice(0, 8) });
      return res.json({ orderId, claimed: true, alreadyClaimed: true });
    }
    console.log("Claim rejected", { orderId, status: order.status });
    return res.status(409).json({ error: "Order is not claimable", status: order.status });
  } catch (e) {
    console.error("Claim order error:", e.message);
    return res.status(500).json({ error: "Could not claim order" });
  }
});

const AGHANIM_ORDERS_URL = "https://api.aghanim.com/s2s/v1/orders";
const CREATE_LIMIT_PER_MINUTE = 10;
const createAttempts = new Map();

function allowCreate(playerId) {
  const now = Date.now();
  const recent = (createAttempts.get(playerId) || []).filter((t) => now - t < 60000);
  if (recent.length >= CREATE_LIMIT_PER_MINUTE) return false;
  recent.push(now);
  createAttempts.set(playerId, recent);
  return true;
}

// Creates an Aghanim order server-side (S2S key stays secret) and returns its checkout URL.
app.post("/api/payment/create", async (req, res) => {
  try {
    const s2sKey = process.env.AGHANIM_S2S_KEY;
    if (!s2sKey) {
      console.error("AGHANIM_S2S_KEY is not set");
      return res.status(500).json({ error: "Payment not configured" });
    }

    const playerId = String(req.body?.playerId || "").trim();
    const sku = String(req.body?.sku || "").trim();
    if (!playerId || !sku || playerId.length > 128 || sku.length > 128) {
      return res.status(400).json({ error: "playerId and sku are required" });
    }

    if (!allowCreate(playerId)) {
      return res.status(429).json({ error: "Too many requests" });
    }

    const body = { player_id: playerId, items: [{ sku }] };
    if (process.env.BACK_TO_GAME_URL) body.back_to_game_url = process.env.BACK_TO_GAME_URL;

    const upstream = await fetch(AGHANIM_ORDERS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${s2sKey}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000)
    });
    if (!upstream.ok) {
      console.error("Aghanim create order failed:", upstream.status, `sku=${sku}`, (await upstream.text()).slice(0, 500));
      return res.status(502).json({ error: "Could not create order" });
    }

    const created = await upstream.json();
    const orderId = created.order_id;
    const checkoutUrl = created.checkout_url;
    if (!orderId || !checkoutUrl) {
      console.error("Aghanim create order: unexpected response", Object.keys(created));
      return res.status(502).json({ error: "Could not create order" });
    }

    // Nothing is stored here: the order is created by the item.add webhook once paid.
    return res.json({ orderId, checkoutUrl });
  } catch (e) {
    console.error("Create order error:", e.message);
    return res.status(500).json({ error: "Could not create order" });
  }
});

// iOS Universal Links: lets https://<this host>/checkout* reopen the game after payment.
app.get("/.well-known/apple-app-site-association", (_req, res) => {
  const teamId = process.env.APPLE_TEAM_ID;
  const bundleId = process.env.APPLE_BUNDLE_ID;
  if (!teamId || !bundleId) return res.status(404).json({ error: "Not found" });

  return res.type("application/json").json({
    applinks: {
      details: [{
        appIDs: [`${teamId}.${bundleId}`],
        components: [{ "/": "/checkout*" }]
      }]
    }
  });
});

// Fallback page when the link opens in a browser instead of the game.
app.get("/checkout-complete", (_req, res) => {
  res.type("html").send("<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>" +
    "<title>Payment complete</title><p style='font-family:sans-serif;text-align:center;margin-top:20vh'>" +
    "Payment complete. You can return to the game.</p>");
});

app.use((req, res) => {
  console.warn("404 Not found:", req.method, req.originalUrl);
  return res.status(404).json({ error: "Not found" });
});

async function start() {
  await connectMongo();
  const port = Number(process.env.PORT || 10000);
  const server = app.listen(port, "0.0.0.0", () => {
    console.log(`Aghanim Payment Server listening on ${port}`);
  });

  const shutdown = async () => {
    server.close(async () => {
      if (mongoClient) await mongoClient.close();
      process.exit(0);
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

start().catch((e) => {
  console.error("Startup failed:", e);
  process.exit(1);
});
