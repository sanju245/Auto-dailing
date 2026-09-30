require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const twilio = require('twilio');

const {
  TWILIO_ACCOUNT_SID, TWILIO_API_KEY_SID, TWILIO_API_KEY_SECRET,
  TWILIO_AUTH_TOKEN, TWILIO_TWIML_APP_SID, TWILIO_CALLER_ID,
  PUBLIC_URL, AGENT_PASSCODE, PORT = 3000,
} = process.env;

const app = express();
app.use(express.urlencoded({ extended: false })); // Twilio webhooks
app.use(express.json());

const mask = n => String(n).replace(/\d(?=\d{4})/g, '*');

const safeEqual = (a = '', b = '') => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

// Voice SDK served from the installed package (no CDN needed)
app.get('/vendor/twilio.min.js', (_req, res) =>
  res.sendFile(path.join(__dirname, 'node_modules/@twilio/voice-sdk/dist/twilio.min.js')));

app.use(express.static(path.join(__dirname, 'public')));
app.get('/agent', (_req, res) => res.sendFile(path.join(__dirname, 'public/agent.html')));

// 1) Access token for the browser phone
app.post('/api/voice/token', (req, res) => {
  if (!AGENT_PASSCODE || !safeEqual(req.body?.passcode, AGENT_PASSCODE))
    return res.status(401).json({ error: 'Invalid passcode' });

  const identity = String(req.body?.identity || 'agent').replace(/[^\w-]/g, '').slice(0, 40) || 'agent';
  const { AccessToken } = twilio.jwt;
  const token = new AccessToken(TWILIO_ACCOUNT_SID, TWILIO_API_KEY_SID, TWILIO_API_KEY_SECRET,
    { identity, ttl: 3600 });
  token.addGrant(new AccessToken.VoiceGrant({
    outgoingApplicationSid: TWILIO_TWIML_APP_SID,
    incomingAllow: false,
  }));
  res.json({ token: token.toJwt(), identity, expiresIn: 3600 });
});

// 2) TwiML App "Voice Request URL" -> POST https://<PUBLIC_URL>/api/voice/outbound
app.post('/api/voice/outbound', (req, res) => {
  const sig = req.get('X-Twilio-Signature') || '';
  if (!twilio.validateRequest(TWILIO_AUTH_TOKEN, sig, `${PUBLIC_URL}/api/voice/outbound`, req.body))
    return res.status(403).send('Invalid signature');

  const to = String(req.body.To || '');
  const vr = new twilio.twiml.VoiceResponse();
  console.log(`[outbound] CallSid=${req.body.CallSid} from=${req.body.From} to=${mask(to)}`);
  if (/^\+[1-9]\d{7,14}$/.test(to)) {
    vr.dial({ callerId: TWILIO_CALLER_ID, answerOnBridge: true }).number({
      statusCallback: `${PUBLIC_URL}/api/voice/status`,
      statusCallbackEvent: 'initiated ringing answered completed',
      statusCallbackMethod: 'POST',
    }, to);
  } else {
    vr.say('The number you entered is not valid.');
  }
  res.type('text/xml').send(vr.toString());
});

// 3) Call progress logs (child leg: initiated / ringing / answered / completed)
app.post('/api/voice/status', (req, res) => {
  const sig = req.get('X-Twilio-Signature') || '';
  if (!twilio.validateRequest(TWILIO_AUTH_TOKEN, sig, `${PUBLIC_URL}/api/voice/status`, req.body))
    return res.status(403).send('Invalid signature');
  const b = req.body;
  console.log(`[status] CallSid=${b.CallSid} parent=${b.ParentCallSid} status=${b.CallStatus} duration=${b.CallDuration || '-'}s`);
  res.sendStatus(204);
});

app.listen(PORT, () => console.log(`AllSafe Dialer on :${PORT}  ->  /agent`));
