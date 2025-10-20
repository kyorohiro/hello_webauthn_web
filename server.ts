import express from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';
import { fileURLToPath } from "node:url";
import "dotenv/config";
import path from "node:path";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const rpID = process.env.RP_ID || "localhost";
const origin = process.env.ORIGIN || "http://localhost:3000";
const publicDir = path.join(__dirname, "public");


const db = new Map<string, any>(); // 超簡易: ユーザー/クレデンシャル保存

const app = express();
app.use (express.json());

// 静的配信（/assets 等）
app.use(express.static(publicDir, {
  // キャッシュしたくないときは↓
  // etag: false, lastModified: false, maxAge: 0, cacheControl: false
}));

// ルート / は必ず index.html を返す
app.get("/", (_req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});


app.post('/api/webauthn/registration/options', async (req, res) => {
  const { userId, username, displayName } = req.body;
  const opts = await generateRegistrationOptions({
    rpName: 'My App',
    rpID,
    // userID: userId,
    userID: isoUint8Array.fromUTF8String(String(userId)),
    userName: username,
    userDisplayName: displayName ?? username,
    authenticatorSelection: {
      residentKey: 'preferred',        // パスキー推奨
      userVerification: 'required',
    },
    attestationType: 'none',
  });
  // ユーザーに紐づく challenge を保存
  db.set(`regChallenge:${userId}`, opts.challenge);
  res.json(opts);
});

app.post('/api/webauthn/registration/verify', async (req, res) => {
  const { userId, attResp } = req.body;
  const expectedChallenge = db.get(`regChallenge:${userId}`);
  const vr = await verifyRegistrationResponse({
    response: attResp,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
  });
  if (!vr.verified || !vr.registrationInfo) return res.status(400).json({ ok:false });
  // 公開鍵などを保存（複数端末=複数パスキーに備えて配列で）
  const creds = (db.get(`creds:${userId}`) ?? []) as any[];
  creds.push({
    // v13: registrationInfo.credential.* が正
    id:        vr.registrationInfo.credential.id,        // Base64URL文字列
    publicKey: vr.registrationInfo.credential.publicKey, // Uint8Array
    counter:   vr.registrationInfo.credential.counter,
    transports:vr.registrationInfo.credential.transports,
  });
  db.set(`creds:${userId}`, creds);
  res.json({ ok: true });
});

app.post('/api/webauthn/authentication/options', async (req, res) => {
  const { userId } = req.body;
  const creds = (db.get(`creds:${userId}`) ?? []) as any[];
  const opts = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    allowCredentials: creds.map(c => ({ id: c.id, type: 'public-key' })),
  });
  db.set(`authChallenge:${userId}`, opts.challenge);
  res.json(opts);
});

app.post('/api/webauthn/authentication/verify', async (req, res) => {
  const { userId, assertionResp } = req.body;
  const expectedChallenge = db.get(`authChallenge:${userId}`);
  const creds = (db.get(`creds:${userId}`) ?? []) as any[];
  const cred = creds.find(c => c.id === assertionResp.id);
  // const cred = creds.find(c => Buffer.compare(c.id, Buffer.from(assertionResp.rawId, 'base64url')) === 0);
  if (!cred) return res.status(400).json({ ok: false });

const vr = await verifyAuthenticationResponse({
   response: assertionResp,
   expectedChallenge,
   expectedOrigin: origin,
   expectedRPID: rpID,
   credential: {
     id: cred.id,                          // DBのcredentialID（Base64URL）
     publicKey: cred.publicKey,            // Uint8Array
     counter: cred.counter ?? 0,
     transports: cred.transports ?? [],
   },
 });
  if (!vr.verified || !vr.authenticationInfo) return res.status(401).json({ ok: false });

  cred.counter = vr.authenticationInfo.newCounter;
  res.json({ ok: true, userId });
});

const main = async () => {
    console.log("Server is starting...");
    app.listen(3000, () => {
        console.log("Server is running on http://localhost:3000");
    });
}

main();