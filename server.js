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
      "SELECT p.id,p.email,p.full_name FROM sessions s JOIN parents p ON p.id=s.parent_id WHERE s.token_hash=$1 AND s.expires_at>NOW()",
      [tokenHash(token)]
    );
    if (!result.rowCount) return res.status(401).json({ error: "Sessiya muddati tugagan. Qayta kiring." });
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
    const result = await pool.query("SELECT id,email,full_name,password_hash FROM parents WHERE email=$1", [email]);
    const parent = result.rows[0];
    if (!parent || !(await bcrypt.compare(password, parent.password_hash))) {
      return res.status(401).json({ error: "Email yoki parol noto'g'ri." });
    }
    await issueSession(parent.id, res);
    const children = await pool.query("SELECT id,display_name,age FROM children WHERE parent_id=$1 ORDER BY created_at", [parent.id]);
    res.json({ parent: { id: parent.id, email: parent.email, full_name: parent.full_name }, children: children.rows });
  } catch (error) { next(error); }
});

app.get("/api/auth/me", requireDb, auth, async (req, res, next) => {
  try {
    const children = await pool.query("SELECT id,display_name,age FROM children WHERE parent_id=$1 ORDER BY created_at", [req.parent.id]);
    res.json({ parent: req.parent, children: children.rows });
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
Asosiy til — adabiy, ravon, tabiiy va grammatik jihatdan to‘g‘ri o‘zbek tili (lotin yozuvi). Imlo, qo‘shimchalar va tinish belgilariga e’tibor ber. Sun’iy tarjimaga o‘xshagan jumlalar tuzma.
Bola boshqa tilni mashq qilayotgan bo‘lsa, misollarni o‘sha tilda ber, izohni sodda o‘zbek tilida tushuntir.
Matematika, o‘qish, yozish va ingliz tilini kichik bosqichlarda o‘rgat. Javoblar aniq, yoshga mos, quvnoq va odatda 2–4 qisqa gapdan iborat bo‘lsin.
Javobni darhol aytib qo‘ymasdan, imkon bo‘lsa bolani fikrlashga undaydigan bitta sodda savol ber. Xatolarni muloyim tuzat, hech qachon uyaltirma. Ovoz chiqarib o‘qishga qulay, sodda jumlalardan foydalan.
Shaxsiy ma’lumot, manzil, telefon, parol yoki maktab nomini so‘rama. Xavfli vaziyatlarda ishonchli kattaga murojaat qilishni ayt.
Tibbiy, moliyaviy yoki xavfli ko‘rsatmalar bermagin. O‘zingni sun’iy intellekt yordamchisi ekaningni yashirma.`;

app.post("/api/ai/guest-tutor", aiLimiter, async (req, res, next) => {
  try {
    if (!ai) return res.status(503).json({ error: "AI hozircha sozlanmagan. Gemini API kalitini Render Environment bo'limida tekshiring." });
    const prompt = clean(req.body?.promptText);
    const childName = clean(req.body?.childName).slice(0, 40) || "Do‘stim";
    const childAge = Math.min(12, Math.max(5, Number(req.body?.childAge) || 7));
    if (!prompt || prompt.length > 2000) return res.status(400).json({ error: "Savol 1–2000 belgi oralig'ida bo'lishi kerak." });
    const response = await ai.models.generateContent({
      model: MODEL,
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: {
        systemInstruction: tutorInstruction + ` Sen hozir ${childName} ismli ${childAge} yoshli bola bilan suhbatlashyapsan. Doimo adabiy, ravon va grammatik jihatdan to‘g‘ri o‘zbek tilida gapir. Iliq, quvnoq, mehribon ustoz ohangidan foydalan; murakkab atamalarni sodda misollar bilan tushuntir. Javoblaring tabiiy og‘zaki nutqqa mos, talaffuz qilishga qulay bo‘lsin. Odatda 2–4 qisqa gap yoz, bitta savol bilan bolani fikrlashga unda. Emoji me’yorida ishlat.`,
        temperature: 0.65,
        maxOutputTokens: 320
      }
    });
    const answer = clean(response.text);
    if (!answer) return res.status(502).json({ error: "AI bo'sh javob qaytardi. Yana urinib ko'ring." });
    res.json({ answer });
  } catch (error) {
    const message = String(error?.message || "");
    if (/429|quota|resource_exhausted/i.test(message)) return res.status(429).json({ error: "AI savollari limiti vaqtincha tugadi. Birozdan keyin urinib ko'ring." });
    next(error);
  }
});

app.post("/api/ai/tutor", requireDb, auth, aiLimiter, async (req, res, next) => {
  try {
    if (!ai) return res.status(503).json({ error: "AI hozircha sozlanmagan. Administrator Gemini kalitini serverga qo'shishi kerak." });
    const childId = clean(req.body.childId);
    const message = clean(req.body.message);
    const subject = clean(req.body.subject);
    if (!/^[0-9a-f-]{36}$/i.test(childId) || !AI_SUBJECTS.has(subject) || !message || message.length > 2000) {
      return res.status(400).json({ error: "Savol yoki fan ma'lumoti noto'g'ri." });
    }
    const owned = await pool.query("SELECT display_name,age FROM children WHERE id=$1 AND parent_id=$2", [childId, req.parent.id]);
    if (!owned.rowCount) return res.status(404).json({ error: "O'quvchi profili topilmadi." });
    const child = owned.rows[0];
    const history = await pool.query(
      "SELECT role,message FROM ai_conversations WHERE child_id=$1 ORDER BY created_at DESC LIMIT 8",
      [childId]
    );
    const contents = history.rows.reverse().map(row => ({ role: row.role, parts: [{ text: row.message }] }));
    contents.push({ role: "user", parts: [{ text: `Fan: ${subject}. O'quvchi: ${child.display_name}, yoshi: ${child.age}. Savol: ${message}` }] });
    const response = await ai.models.generateContent({
      model: MODEL,
      contents,
      config: { systemInstruction: tutorInstruction + " Javoblaring o‘zbek tilida ravon, tabiiy, quvnoq va bolaga tushunarli bo‘lsin. Ovozli o‘qishga mos qisqa jumlalardan foydalan.", temperature: 0.65, maxOutputTokens: 500 }
    });
    const answer = clean(response.text);
    if (!answer) throw new Error("Gemini bo'sh javob qaytardi.");
    await pool.query(
      "INSERT INTO ai_conversations(child_id,role,message) VALUES($1,'user',$2),($1,'model',$3)",
      [childId, message, answer]
    );
    res.json({ answer });
  } catch (error) {
    const message = String(error?.message || "");
    if (/429|quota|resource_exhausted/i.test(message)) return res.status(429).json({ error: "AI savollari limiti vaqtincha tugadi. Birozdan keyin yana urinib ko'ring." });
    next(error);
  }
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
  res.status(500).json({ error: "Serverda xatolik yuz berdi. Iltimos, keyinroq urinib ko'ring." });
});
app.listen(PORT, () => console.log(`Bilimdon Kids API listening on ${PORT}`));
