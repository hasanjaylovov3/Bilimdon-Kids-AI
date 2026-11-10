import "dotenv/config";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import pg from "pg";
import { GoogleGenAI } from "@google/genai";

const { Pool } = pg;
const app = express();
const isProd = process.env.NODE_ENV === "production";
const PORT = Number(process.env.PORT || 3000);
const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : undefined
}) : null;
const ai = process.env.GEMINI_API_KEY ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY }) : null;
const MODEL = process.env.GEMINI_MODEL || "gemini-3.8-flash";
const FALLBACK_MODEL = process.env.GEMINI_FALLBACK_MODEL || "gemini-3.5-flash-lite";
const TTS_MODEL = process.env.GEMINI_TTS_MODEL || "gemini-3.8-flash-lite-tts";
async function generateTutorContent({ input, systemInstruction = tutorInstruction, temperature = 0.35, maxOutputTokens = 300 }) {
  if (!ai) throw new Error("GEMINI_API_KEY serverda sozlanmagan.");
  const models = [...new Set([MODEL, FALLBACK_MODEL])];
  let lastError;
  for (const model of models) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        return await ai.interactions.create({
          model, input, system_instruction: systemInstruction,
          generation_config: { temperature, max_output_tokens: maxOutputTokens }, store: false
        });
      } catch (error) {
        lastError = error;
        const message = String(error?.message || "");
        const transient = /429|503|500|502|504|UNAVAILABLE|high demand|overloaded|RESOURCE_EXHAUSTED/i.test(message) || [429,500,502,503,504].includes(Number(error?.status || error?.code));
        if (!transient) throw error;
        if (attempt === 0 && model === MODEL) await new Promise(resolve => setTimeout(resolve, 350));
        else break;
      }
    }
  }
  throw lastError || new Error("AI modellari vaqtincha javob bermayapti.");
}

async function generateTutorSpeech(input) {
  if (!ai) throw new Error("GEMINI_API_KEY serverda sozlanmagan.");
  const models = [...new Set([TTS_MODEL, "gemini-3.8-flash-tts"])];
  let lastError;
  for (const model of models) {
    try {
      return await ai.interactions.create({
        model,
        input: [{
          type: "user_input",
          content: [{
            type: "text",
            text: input,
            annotations: [{
              type: "speech_metadata",
              style: "Fluent natural Northern Uzbek, warm friendly teacher, clear articulation, lively but unhurried pace, no breathy ending, finish cleanly"
            }]
          }]
        }],
        response_format: { type: "audio" },
        generation_config: { speech_config: [{ voice: "Leda" }] },
        store: false
      });
    } catch (error) {
      lastError = error;
      const message = String(error?.message || "");
      const transient = /429|503|500|502|504|UNAVAILABLE|high demand|overloaded|RESOURCE_EXHAUSTED/i.test(message) || [429,500,502,503,504].includes(Number(error?.status || error?.code));
      if (!transient) throw error;
    }
  }
  throw lastError || new Error("Ovoz modellari vaqtincha javob bermayapti.");
}

const SESSION_DAYS = Math.min(30, Math.max(1, Number(process.env.SESSION_DAYS || 14)));

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(cookieParser());
app.use(express.static("public", { extensions: ["html"] }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: "draft-8", legacyHeaders: false });
const aiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: "draft-8", legacyHeaders: false });
const tokenHash = value => crypto.createHash("sha256").update(value).digest("hex");
const clean = value => String(value ?? "").trim();

function requireDb(req, res, next) {
  if (!pool) return res.status(503).json({ error: "Ma'lumotlar bazasi sozlanmagan." });
  next();
}
async function auth(req, res, next) {
  try {
    const token = req.cookies.bk_session;
    if (!token) return res.status(401).json({ error: "Avval tizimga kiring." });
    const result = await pool.query(
      "SELECT p.id,p.email,p.full_name,p.is_blocked FROM sessions s JOIN parents p ON p.id=s.parent_id WHERE s.token_hash=$1 AND s.expires_at>NOW()",
      [tokenHash(token)]
    );
    if (!result.rowCount) return res.status(401).json({ error: "Sessiya muddati tugagan. Qayta kiring." });
    if (result.rows[0].is_blocked) return res.status(403).json({ error: "Hisob vaqtincha bloklangan. Administratorga murojaat qiling." });
    req.parent = result.rows[0];
    next();
  } catch (error) { next(error); }
}
function setSession(res, token, expires) {
  res.cookie("bk_session", token, {
    httpOnly: true, secure: isProd, sameSite: "lax", path: "/", expires
  });
}
async function issueSession(parentId, res) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000);
  await pool.query("INSERT INTO sessions(token_hash,parent_id,expires_at) VALUES($1,$2,$3)", [tokenHash(token), parentId, expires]);
  setSession(res, token, expires);
}

app.get("/api/health", async (_req, res) => {
  let database = "not_configured";
  if (pool) {
    try { await pool.query("SELECT 1"); database = "ok"; }
    catch { database = "error"; }
  }
  res.json({ ok: true, service: "bilimdon-kids-api", database, gemini: Boolean(ai) });
});

app.post("/api/auth/register", requireDb, authLimiter, async (req, res, next) => {
  const fullName = clean(req.body.fullName);
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || "");
  const childName = clean(req.body.childName);
  const age = Number(req.body.age);
  if (fullName.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 10 || password.length > 72 || childName.length < 1 || childName.length > 40 ||
      !Number.isInteger(age) || age < 5 || age > 12) {
    return res.status(400).json({ error: "Ma'lumotlarni tekshiring. Parol kamida 10 belgidan iborat bo'lsin." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const hash = await bcrypt.hash(password, 12);
    const parent = await client.query(
      "INSERT INTO parents(full_name,email,password_hash) VALUES($1,$2,$3) RETURNING id,email,full_name",
      [fullName, email, hash]
    );
    const child = await client.query(
      "INSERT INTO children(parent_id,display_name,age) VALUES($1,$2,$3) RETURNING id,display_name,age",
      [parent.rows[0].id, childName, age]
    );
    await client.query("COMMIT");
    await issueSession(parent.rows[0].id, res);
    res.status(201).json({ parent: parent.rows[0], child: child.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") return res.status(409).json({ error: "Bu email bilan hisob mavjud." });
    next(error);
  } finally { client.release(); }
});

app.post("/api/auth/login", requireDb, authLimiter, async (req, res, next) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const password = String(req.body.password || "");
    const result = await pool.query("SELECT id,email,full_name,password_hash,is_blocked FROM parents WHERE email=$1", [email]);
    const parent = result.rows[0];
    if (!parent || !(await bcrypt.compare(password, parent.password_hash))) {
      return res.status(401).json({ error: "Email yoki parol noto'g'ri." });
    }
    if (parent.is_blocked) return res.status(403).json({ error: "Hisob vaqtincha bloklangan. Administrator bilan bog‘laning." });
    await issueSession(parent.id, res);
    const children = await pool.query("SELECT id,display_name,age FROM children WHERE parent_id=$1 ORDER BY created_at", [parent.id]);
    res.json({ parent: { id: parent.id, email: parent.email, full_name: parent.full_name, is_admin: Boolean(process.env.ADMIN_EMAIL && parent.email === process.env.ADMIN_EMAIL.toLowerCase()) }, children: children.rows });
  } catch (error) { next(error); }
});

app.get("/api/auth/me", requireDb, auth, async (req, res, next) => {
  try {
    const children = await pool.query("SELECT id,display_name,age FROM children WHERE parent_id=$1 ORDER BY created_at", [req.parent.id]);
    res.json({ parent: { ...req.parent, is_admin: Boolean(process.env.ADMIN_EMAIL && req.parent.email === process.env.ADMIN_EMAIL.toLowerCase()) }, children: children.rows });
  } catch (error) { next(error); }
});
app.post("/api/auth/logout", requireDb, async (req, res, next) => {
  try {
    const token = req.cookies.bk_session;
    if (token) await pool.query("DELETE FROM sessions WHERE token_hash=$1", [tokenHash(token)]);
    res.clearCookie("bk_session", { httpOnly: true, secure: isProd, sameSite: "lax", path: "/" });
    res.status(204).end();
  } catch (error) { next(error); }
});

const SUBJECTS = new Set(["math", "reading", "writing", "english"]);
const AI_SUBJECTS = new Set([...SUBJECTS, "general"]);
const tutorInstruction = `Sen Bilimdon Kids platformasining 5–12 yoshli bolalar uchun mehribon, sabrli va bilimdon AI ustozisan.
ASOSIY VA MAJBURIY JAVOB TILI — O‘ZBEK TILI, LOTIN YOZUVI. Bola ruscha yoki inglizcha yozsa ham, alohida ravishda boshqa tilda javob so‘ramaguncha, javobni o‘zbekcha ber.
O‘zbek tilida ona tilidek tabiiy, ravon va grammatik jihatdan to‘g‘ri gapir. Toshkent va adabiy o‘zbek nutqiga xos sodda iboralarni tanla. Ruscha yoki inglizcha gap tuzilishini o‘zbekchaga ko‘chirib qo‘yma; so‘zma-so‘z tarjima, sun’iy iboralar va keraksiz chet so‘zlardan qoch.
Bola bilan mehribon ustozdek, “sen” deb samimiy gaplash. “Barakalla”, “Keling, birga topamiz”, “Ajoyib fikr!” kabi tabiiy bolalarcha ruhlantiruvchi iboralarni me’yorida ishlat.
Matematika, o‘qish, yozish va ingliz tilini kichik bosqichlarda o‘rgat. Javoblar aniq, yoshga mos, quvnoq va odatda 2–4 qisqa gapdan iborat bo‘lsin. Ovoz chiqarib o‘qishga qulay, qisqa va ravon jumlalar tuz.
Javob yuborishdan oldin ichingda o‘zbekcha imlo, qo‘shimcha va gap tuzilishini tekshir. Bitta sodda savol bilan bolani fikrlashga unda; xatolarini muloyim tuzat va hech qachon uyaltirma.
Shaxsiy ma’lumot, manzil, telefon, parol yoki maktab nomini so‘rama. Xavfli vaziyatlarda ishonchli kattaga murojaat qilishni ayt.
Tibbiy, moliyaviy yoki xavfli ko‘rsatmalar bermagin. O‘zingni sun’iy intellekt yordamchisi ekaningni yashirma.`;

app.post("/api/ai/speech", aiLimiter, async (req, res, next) => {
  try {
    if (!ai) return res.status(503).json({ error: "Ovozli AI hozircha sozlanmagan." });
    const text = clean(req.body?.text);
    if (!text || text.length > 1200) {
      return res.status(400).json({ error: "Ovozga aylantiriladigan matn 1–1200 belgi bo‘lishi kerak." });
    }
    const interaction = await generateTutorSpeech(text);
    const audioData = interaction.output_audio?.data;
    if (!audioData) return res.status(502).json({ error: "Gemini ovoz qaytara olmadi. Qayta urinib ko‘ring." });
    const wav = Buffer.from(audioData, "base64");
    if (wav.length < 48 || wav.toString("ascii", 0, 4) !== "RIFF") {
      return res.status(502).json({ error: "Gemini audio formati noto‘g‘ri qaytdi." });
    }
    // WAV ichidagi oxirgi 240 ms oxirgi shovqin qismini olib tashlab, 100 ms yumshoq yakunlaymiz.
    const dataMarker = wav.indexOf("data", 12, "ascii");
    if (dataMarker > 0) {
      const dataStart = dataMarker + 8;
      const sampleRate = wav.readUInt32LE(24);
      const channels = wav.readUInt16LE(22);
      const bytesPerSample = wav.readUInt16LE(34) / 8;
      const frameBytes = channels * bytesPerSample;
      const dataLength = wav.readUInt32LE(dataMarker + 4);
      const originalEnd = Math.min(wav.length, dataStart + dataLength);
      const trimFrames = Math.floor(sampleRate * 0.24);
      const trimBytes = Math.min(Math.max(0, originalEnd - dataStart - frameBytes * 8), trimFrames * frameBytes);
      const cleanEnd = originalEnd - trimBytes;
      const fadeBytes = Math.min(cleanEnd - dataStart, Math.floor(sampleRate * 0.10) * frameBytes);
      for (let offset = cleanEnd - fadeBytes; offset + 1 < cleanEnd; offset += 2) {
        const progress = (offset - (cleanEnd - fadeBytes)) / Math.max(1, fadeBytes - 2);
        const gain = Math.cos(progress * Math.PI / 2);
        wav.writeInt16LE(Math.round(wav.readInt16LE(offset) * gain), offset);
      }
      const cleanWav = Buffer.concat([wav.subarray(0, cleanEnd)]);
      cleanWav.writeUInt32LE(cleanWav.length - 8, 4);
      cleanWav.writeUInt32LE(cleanEnd - dataStart, dataMarker + 4);
      res.set("Content-Type", "audio/wav");
      res.set("Cache-Control", "no-store");
      return res.json({ audio: cleanWav.toString("base64"), mimeType: "audio/wav" });
    }
    res.json({ audio: audioData, mimeType: "audio/wav" });
  } catch (error) {
    const message = String(error?.message || "");
    if (/429|quota|resource_exhausted/i.test(message)) return res.status(429).json({ error: "Ovoz yaratish limiti vaqtincha tugadi. Birozdan keyin yana urinib ko‘ring." });
    console.error("Gemini TTS interaction error:", message);
    next(error);
  }
});
app.post("/api/ai/guest-tutor", aiLimiter, async (req, res, next) => {
  try {
    if (!ai) return res.status(503).json({ error: "AI kaliti serverda sozlanmagan. Administrator Render Environment sozlamasini tekshirishi kerak." });
    const prompt = clean(req.body?.promptText);
    const childName = clean(req.body?.childName).slice(0, 40) || "Do‘stim";
    const childAge = Math.min(12, Math.max(5, Number(req.body?.childAge) || 7));
    if (!prompt || prompt.length > 2000) return res.status(400).json({ error: "Savol 1–2000 belgi oralig‘ida bo‘lishi kerak." });
    const response = await generateTutorContent({
      input: `O‘quvchi: ${childName}, yoshi: ${childAge}. Savoli: ${prompt}`,
      systemInstruction: tutorInstruction,
      temperature: 0.35,
      maxOutputTokens: 300
    });
    const answer = clean(response.output_text);
    if (!answer) return res.status(502).json({ error: "AI bo‘sh javob qaytardi. Yana urinib ko‘ring." });
    res.json({ answer });
  } catch (error) {
    const message = String(error?.message || "");
    if (/429|quota|resource_exhausted/i.test(message)) return res.status(429).json({ error: "AI savollari limiti vaqtincha tugadi. Birozdan keyin urinib ko‘ring." });
    console.error("Gemini tutor interaction error:", message);
    next(error);
  }
});
app.post("/api/ai/tutor", requireDb, auth, aiLimiter, async (req, res, next) => {
  try {
    if (!ai) return res.status(503).json({ error: "AI kaliti serverda sozlanmagan. Administrator Gemini kalitini tekshirishi kerak." });
    const childId = clean(req.body.childId);
    const message = clean(req.body.message);
    const subject = clean(req.body.subject);
    if (!/^[0-9a-f-]{36}$/i.test(childId) || !AI_SUBJECTS.has(subject) || !message || message.length > 2000) {
      return res.status(400).json({ error: "Savol yoki fan ma’lumoti noto‘g‘ri." });
    }
    const owned = await pool.query("SELECT display_name,age FROM children WHERE id=$1 AND parent_id=$2", [childId, req.parent.id]);
    if (!owned.rowCount) return res.status(404).json({ error: "O‘quvchi profili topilmadi." });
    const child = owned.rows[0];
    const history = await pool.query(
      "SELECT role,message FROM ai_conversations WHERE child_id=$1 ORDER BY created_at DESC LIMIT 6",
      [childId]
    );
    const transcript = history.rows.reverse().map(row => (row.role === "user" ? "Bola: " : "Ustoz: ") + row.message).join("\n");
    const response = await generateTutorContent({
      input: `O‘quvchi: ${child.display_name}, yoshi: ${child.age}. Fan: ${subject}.\n${transcript ? "Oldingi suhbat:\n" + transcript + "\n" : ""}Bolaning yangi savoli: ${message}`,
      systemInstruction: tutorInstruction,
      temperature: 0.35,
      maxOutputTokens: 300
    });
    const answer = clean(response.output_text);
    if (!answer) throw new Error("Gemini bo‘sh javob qaytardi.");
    await pool.query(
      "INSERT INTO ai_conversations(child_id,role,message) VALUES($1,'user',$2),($1,'model',$3)",
      [childId, message, answer]
    );
    res.json({ answer });
  } catch (error) {
    const message = String(error?.message || "");
    if (/429|quota|resource_exhausted/i.test(message)) return res.status(429).json({ error: "AI savollari limiti vaqtincha tugadi. Birozdan keyin urinib ko‘ring." });
    console.error("Gemini tutor interaction error:", message);
    next(error);
  }
});

function requireAdmin(req, res, next) {
  const adminEmail = clean(process.env.ADMIN_EMAIL).toLowerCase();
  if (!adminEmail) return res.status(503).json({ error: "Admin panel uchun Render Environment’da ADMIN_EMAIL sozlanmagan." });
  if (req.parent.email !== adminEmail) return res.status(403).json({ error: "Bu bo‘lim faqat administrator uchun." });
  next();
}
app.get("/api/content", async (_req, res, next) => {
  try {
    if (!pool) return res.json({ items: [] });
    const result = await pool.query("SELECT id,kind,title,description,image_url,content_data,created_at FROM learning_content WHERE is_published=TRUE ORDER BY created_at DESC");
    res.json({ items: result.rows });
  } catch (error) { next(error); }
});
app.get("/api/admin/overview", requireDb, auth, requireAdmin, async (_req, res, next) => {
  try {
    const [users, content, stats] = await Promise.all([
      pool.query("SELECT p.id,p.email,p.full_name,p.is_blocked,p.created_at,COALESCE(json_agg(json_build_object('id',c.id,'name',c.display_name,'age',c.age)) FILTER (WHERE c.id IS NOT NULL),'[]'::json) AS children FROM parents p LEFT JOIN children c ON c.parent_id=p.id GROUP BY p.id ORDER BY p.created_at DESC"),
      pool.query("SELECT id,kind,title,description,image_url,content_data,is_published,created_at FROM learning_content ORDER BY created_at DESC"),
      pool.query("SELECT (SELECT COUNT(*)::int FROM parents) AS users,(SELECT COUNT(*)::int FROM children) AS children,(SELECT COUNT(*)::int FROM learning_content) AS content,(SELECT COUNT(*)::int FROM parents WHERE is_blocked=TRUE) AS blocked")
    ]);
    res.json({ users: users.rows, content: content.rows, stats: stats.rows[0] });
  } catch (error) { next(error); }
});
app.patch("/api/admin/users/:id/block", requireDb, auth, requireAdmin, async (req, res, next) => {
  try {
    const blocked = Boolean(req.body?.blocked);
    const result = await pool.query("UPDATE parents SET is_blocked=$1 WHERE id=$2 RETURNING id,is_blocked", [blocked, req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: "Foydalanuvchi topilmadi." });
    if (blocked) await pool.query("DELETE FROM sessions WHERE parent_id=$1", [req.params.id]);
    res.json({ user: result.rows[0] });
  } catch (error) { next(error); }
});
app.post("/api/admin/users/:id/reset-password", requireDb, auth, requireAdmin, async (req, res, next) => {
  try {
    const temporaryPassword = crypto.randomBytes(9).toString("base64url");
    const hash = await bcrypt.hash(temporaryPassword, 12);
    const result = await pool.query("UPDATE parents SET password_hash=$1 WHERE id=$2 RETURNING id,email", [hash, req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: "Foydalanuvchi topilmadi." });
    await pool.query("DELETE FROM sessions WHERE parent_id=$1", [req.params.id]);
    res.json({ email: result.rows[0].email, temporaryPassword });
  } catch (error) { next(error); }
});
app.post("/api/admin/content", requireDb, auth, requireAdmin, async (req, res, next) => {
  try {
    const kind = clean(req.body?.kind);
    const title = clean(req.body?.title);
    const description = clean(req.body?.description).slice(0, 1200);
    const imageUrl = clean(req.body?.imageUrl);
    const contentData = req.body?.contentData && typeof req.body.contentData === "object" ? req.body.contentData : {};
    if (!["lesson","image","game"].includes(kind) || title.length < 2 || title.length > 100 ||
        imageUrl.length > 1000 || (imageUrl && !imageUrl.startsWith("https://"))) {
      return res.status(400).json({ error: "Tur, sarlavha yoki HTTPS rasm havolasini tekshiring." });
    }
    if (kind === "game") {
      const options = Array.isArray(contentData.options) ? contentData.options.map(clean).filter(Boolean).slice(0, 6) : [];
      const answer = clean(contentData.answer);
      if (!clean(contentData.question) || options.length < 2 || !options.includes(answer)) {
        return res.status(400).json({ error: "O‘yin savoli, kamida 2 ta variant va variantlar ichidagi to‘g‘ri javobni kiriting." });
      }
      contentData.options = options;
      contentData.answer = answer;
      contentData.question = clean(contentData.question).slice(0, 300);
    }
    const result = await pool.query(
      "INSERT INTO learning_content(kind,title,description,image_url,content_data,is_published) VALUES($1,$2,$3,$4,$5,TRUE) RETURNING id,kind,title,description,image_url,content_data,is_published,created_at",
      [kind,title,description,imageUrl || null,JSON.stringify(contentData)]
    );
    res.status(201).json({ item: result.rows[0] });
  } catch (error) { next(error); }
});
app.delete("/api/admin/content/:id", requireDb, auth, requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query("DELETE FROM learning_content WHERE id=$1 RETURNING id", [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: "Material topilmadi." });
    res.json({ deleted: true });
  } catch (error) { next(error); }
});

app.post("/api/progress", requireDb, auth, async (req, res, next) => {
  try {
    const { childId, subject, activity, score, details = {} } = req.body || {};
    if (!/^[0-9a-f-]{36}$/i.test(String(childId)) || !SUBJECTS.has(subject) ||
        !clean(activity) || clean(activity).length > 100 ||
        (score !== null && score !== undefined && (!Number.isFinite(Number(score)) || Number(score) < 0 || Number(score) > 100))) {
      return res.status(400).json({ error: "Natija ma'lumotlari noto'g'ri." });
    }
    const owned = await pool.query("SELECT 1 FROM children WHERE id=$1 AND parent_id=$2", [childId, req.parent.id]);
    if (!owned.rowCount) return res.status(404).json({ error: "O'quvchi topilmadi." });
    await pool.query(
      "INSERT INTO learning_progress(child_id,subject,activity,score,details) VALUES($1,$2,$3,$4,$5)",
      [childId, subject, clean(activity), score ?? null, JSON.stringify(details)]
    );
    res.status(201).json({ saved: true });
  } catch (error) { next(error); }
});

app.get("/api/progress/:childId", requireDb, auth, async (req, res, next) => {
  try {
    const owned = await pool.query("SELECT 1 FROM children WHERE id=$1 AND parent_id=$2", [req.params.childId, req.parent.id]);
    if (!owned.rowCount) return res.status(404).json({ error: "O'quvchi topilmadi." });
    const rows = await pool.query(
      "SELECT subject,activity,score,details,created_at FROM learning_progress WHERE child_id=$1 ORDER BY created_at DESC LIMIT 100",
      [req.params.childId]
    );
    res.json({ progress: rows.rows });
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  console.error("API error:", error?.message || error);
  const status = Number(error?.status || error?.code || error?.error?.code || 0);
  if (status === 503 || status === 404 || /503|404|NOT_FOUND|UNAVAILABLE|high demand|overloaded/i.test(String(error?.message || ""))) {
    return res.status(503).json({ error: "AI modeli hozircha javob bermayapti. Server modeli sozlamasi tekshirilishi kerak." });
  }
  res.status(500).json({ error: "Serverda xatolik yuz berdi. Iltimos, keyinroq urinib ko'ring." });
});
async function startServer() {
  if (pool) {
    await pool.query("ALTER TABLE parents ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE");
    await pool.query("CREATE TABLE IF NOT EXISTS learning_content (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), kind TEXT NOT NULL CHECK (kind IN ('lesson','image','game')), title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', image_url TEXT, content_data JSONB NOT NULL DEFAULT '{}'::jsonb, is_published BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  }
  app.listen(PORT, () => console.log("Bilimdon Kids API listening on " + PORT));
}
startServer().catch(error => { console.error("Database initialization failed:", error.message); process.exit(1); });
