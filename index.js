// index.js
// Tiny TwiML server for Twilio <Connect><Stream> with security hardening.

import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import basicAuth from "basic-auth";
import { twiml as Twiml, validateRequest } from "twilio";
import dotenv from "dotenv";
dotenv.config();

const {
  PORT = 3000,
  STREAM_WSS_URL,           // e.g. wss://ws-gateway.yourdomain.com/stream
  TWILIO_AUTH_TOKEN,        // from Twilio console (used to validate signatures)
  BASIC_AUTH_USER,          // optional extra auth layer
  BASIC_AUTH_PASS,          // optional extra auth layer
  ALLOWLIST_CIDRS,          // optional CSV of CIDRs to allow (e.g. Twilio media webhooks)
} = process.env;

if (!STREAM_WSS_URL || !TWILIO_AUTH_TOKEN) {
  console.error("Missing STREAM_WSS_URL or TWILIO_AUTH_TOKEN in env");
  process.exit(1);
}

const app = express();
app.set("trust proxy", true);

// Security headers + HSTS
app.use(helmet({ hsts: { maxAge: 15552000, includeSubDomains: true, preload: true } }));

// Basic rate limit (Twilio hits these a few times per call; keep generous)
app.use(rateLimit({ windowMs: 60 * 1000, max: 60 }));

// Twilio sends x-www-form-urlencoded by default
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Optional: Basic Auth (extra layer)
function requireBasicAuth(req, res, next) {
  if (!BASIC_AUTH_USER || !BASIC_AUTH_PASS) return next();
  const creds = basicAuth(req);
  if (!creds || creds.name !== BASIC_AUTH_USER || creds.pass !== BASIC_AUTH_PASS) {
    res.set("WWW-Authenticate", 'Basic realm="twiml"');
    return res.status(401).send("Unauthorized");
  }
  next();
}

// Optional: simple IP allowlist (be careful with proxies; rely primarily on Twilio signature)
function ipAllowed(req) {
  if (!ALLOWLIST_CIDRS) return true;
  // Minimal check (production: use a CIDR lib like ip-cidr or ipaddr.js)
  const allowed = ALLOWLIST_CIDRS.split(",").map(s => s.trim());
  const ip = (req.headers["x-forwarded-for"] || req.ip || "").toString();
  // Fallback: just exact match list for now
  return allowed.includes(ip);
}

function requireIpAllowlist(req, res, next) {
  if (!ALLOWLIST_CIDRS) return next();
  if (!ipAllowed(req)) return res.status(403).send("Forbidden");
  next();
}

// Twilio signature verification middleware
function verifyTwilio(req, res, next) {
  const signature = req.get("X-Twilio-Signature");
  const url = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  const params = req.method === "POST" ? req.body : {};
  const ok = validateRequest(TWILIO_AUTH_TOKEN, signature, url, params);
  if (!ok) return res.status(403).send("Invalid Twilio signature");
  next();
}

app.get("/health", (req, res) => res.status(200).send("ok"));

// Main TwiML endpoint
app.post("/voice", requireBasicAuth, requireIpAllowlist, verifyTwilio, (req, res) => {
  const twiml = new Twiml.VoiceResponse();

  // Bidirectional media stream to your WS gateway (which pipes to Hume EVI)
  const connect = twiml.connect();
  connect.stream({
    url: STREAM_WSS_URL,
    track: "both_tracks",      // send and receive audio
    statusCallback: req.protocol + "://" + req.get("host") + "/status",
    statusCallbackMethod: "POST",
  });

  res.type("text/xml");
  res.send(twiml.toString());
});

// Status callbacks for metrics
app.post("/status", requireBasicAuth, verifyTwilio, (req, res) => {
  // Typical fields: CallSid, CallStatus, From, To, Timestamp, CallDuration, etc.
  // For now: log; in production: forward to n8n webhook or DB.
  console.log("Twilio Status:", req.body);
  res.status(200).send("ok");
});

app.listen(PORT, () => console.log(`TwiML server listening on :${PORT}`));
