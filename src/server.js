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
            $setOnInsert: { createdAt: new Date() }
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

app.get("/api/payment/status/:orderId", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim();
    const playerId = String(req.query.playerId || "").trim();
    if (!orderId || !playerId) {
      return res.status(400).json({ error: "orderId and playerId are required" });
    }

    const order = await db.collection("payment_orders").findOne({ _id: orderId });
    if (!order) return res.json({ orderId, status: "PENDING" });
    if (order.playerId !== playerId) return res.status(404).json({ error: "Order not found" });

    return res.json({
      orderId: order.orderId,
      playerId: order.playerId,
      status: order.status,
      items: order.items || [],
      sandbox: Boolean(order.sandbox),
      paidAt: order.paidAt || null,
      updatedAt: order.updatedAt || null
    });
  } catch (e) {
    console.error("Payment status error:", e.message);
    return res.status(500).json({ error: "Could not retrieve payment status" });
  }
});

app.use((_req, res) => res.status(404).json({ error: "Not found" }));

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
