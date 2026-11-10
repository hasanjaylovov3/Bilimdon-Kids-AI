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
const liveAi = process.env.GEMINI_API_KEY ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY, httpOptions: { apiVersion: "v1alpha" } }) : null;
const MODEL = process.env.GEMINI_MODEL || "gemini-3.8-flash";
const FALLBACK_MODEL = process.env.GEMINI_FALLBACK_MODEL || "gemini-3.5-flash-lite";
const LIVE_MODEL = process.env.GEMINI_LIVE_MODEL || "gemini-3.1-flash-live-preview";
async function generateTutorContent({ input, systemInstruction = tutorInstruction, temperature = 0.25, maxOutputTokens = 180 }) {
  if (!ai) throw new Error("AI Ustoz kaliti serverda sozlanmagan.");
  const models = [...new Set([MODEL, FALLBACK_MODEL].filter(Boolean))];
  let lastError;
  // Tezkor rejim: asosiy modelga bir marta murojaat qilamiz; faqat xato bo‘lsa zaxira model sinovdan o‘tadi.
  for (const model of models) {
    try {
      return await ai.interactions.create({
        model, input, system_instruction: systemInstruction,
        generation_config: { temperature, max_output_tokens: maxOutputTokens }, store: false
      });
    } catch (error) {
      lastError = error;
      const status = Number(error?.status || error?.code || 0);
      if (status === 401 || status === 403 || /API key|permission|unauthorized/i.test(String(error?.message || ""))) throw error;
    }
  }
  throw lastError || new Error("AI modeli vaqtincha javob bermayapti.");
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
  res.json({ ok: true, service: "bilimdon-kids-api", database, aiConfigured: Boolean(ai) });
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

app.get("/api/ai/status", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ configured: Boolean(ai), model: MODEL, liveModel: LIVE_MODEL, database: Boolean(pool), mode: "realtime" });
});
app.get("/api/auth/me", requireDb, auth, async (req, res, next) => {
  try {
    const children = await pool.query("SELECT id,display_name,age FROM children WHERE parent_id=$1 ORDER BY created_at", [req.parent.id]);
    res.json({ parent: { ...req.parent, is_admin: Boolean(process.env.ADMIN_EMAIL && req.parent.email === process.env.ADMIN_EMAIL.toLowerCase()) }, children: children.rows });
  } catch (error) { next(error); }
});
app.patch("/api/profile", requireDb, auth, async (req, res, next) => {
  try {
    const fullName = clean(req.body?.fullName);
    const childName = clean(req.body?.childName);
    const age = Number(req.body?.age);
    const childId = clean(req.body?.childId);
    const currentPassword = String(req.body?.currentPassword || "");
    const newPassword = String(req.body?.newPassword || "");
    if (fullName.length < 2 || fullName.length > 100 || childName.length < 1 || childName.length > 40 ||
        !Number.isInteger(age) || age < 5 || age > 12 || !/^[0-9a-f-]{36}$/i.test(childId)) {
      return res.status(400).json({ error: "Ism, bola ismi yoki yosh ma’lumotlarini tekshiring." });
    }
    const child = await pool.query("SELECT id FROM children WHERE id=$1 AND parent_id=$2", [childId, req.parent.id]);
    if (!child.rowCount) return res.status(404).json({ error: "Bola profili topilmadi." });
    if (newPassword) {
      if (newPassword.length < 10 || newPassword.length > 72 || !currentPassword) {
        return res.status(400).json({ error: "Yangi parol kamida 10 belgi bo‘lsin va joriy parolni kiriting." });
      }
      const stored = await pool.query("SELECT password_hash FROM parents WHERE id=$1", [req.parent.id]);
      if (!stored.rowCount || !(await bcrypt.compare(currentPassword, stored.rows[0].password_hash))) {
        return res.status(401).json({ error: "Joriy parol noto‘g‘ri." });
      }
      const hash = await bcrypt.hash(newPassword, 12);
      await pool.query("UPDATE parents SET full_name=$1,password_hash=$2 WHERE id=$3", [fullName, hash, req.parent.id]);
      await pool.query("DELETE FROM sessions WHERE parent_id=$1 AND token_hash<>$2", [req.parent.id, tokenHash(req.cookies.bk_session)]);
    } else {
      await pool.query("UPDATE parents SET full_name=$1 WHERE id=$2", [fullName, req.parent.id]);
    }
    const updatedChild = await pool.query("UPDATE children SET display_name=$1,age=$2 WHERE id=$3 AND parent_id=$4 RETURNING id,display_name,age", [childName, age, childId, req.parent.id]);
    res.json({ parent: { id: req.parent.id, email: req.parent.email, full_name: fullName, is_admin: Boolean(process.env.ADMIN_EMAIL && req.parent.email === process.env.ADMIN_EMAIL.toLowerCase()) }, child: updatedChild.rows[0] });
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
const AUTHOR_CONTEXT = `
RASMIY DASTUR HAQIDA MA'LUMOT — BU MA'LUMOTNI O'ZGARTIRMANG:
Dastur nomi: «Bilimdon Kids» — Sun’iy intellektga asoslangan interaktiv bolalar ta’lim platformasi.
Dastur muallifi: Saparova Matluba.
Oliygoh: Termiz davlat pedagogika instituti.
Fakultet va maqomi: Boshlang'ich ta'lim fakulteti talabasi.
Yil: 2026.

Agar bola "Seni kim yaratgan?", "Dastur muallifi kim?" yoki shunga o'xshash savol bersa, aynan shu rasmiy ma'lumotga tayangan holda sodda javob ber:
"Meni Saparova Matluba yaratgan. U Termiz davlat pedagogika instituti Boshlang'ich ta'lim fakulteti talabasi. Men «Bilimdon Kids» nomli sun’iy intellektga asoslangan interaktiv bolalar ta’lim platformasining AI ustoziman."

Bu savollarga "dasturchilar jamoasi", "kompaniya" yoki boshqa muallifni aytib javob berma. Muallif haqida ushbu ro'yxatda yo'q ma'lumotlarni to'qib chiqarmagin.
`;

const tutorInstruction = `${AUTHOR_CONTEXT}
Sen Bilimdon Kids platformasining 5–12 yoshli bolalar uchun mehribon, sabrli va bilimdon AI ustozisan.
ASOSIY VA MAJBURIY JAVOB TILI — O‘ZBEK TILI, LOTIN YOZUVI. Bola ruscha yoki inglizcha yozsa ham, alohida ravishda boshqa tilda javob so‘ramaguncha, javobni o‘zbekcha ber.
O‘zbek tilida ona tilidek tabiiy, ravon va grammatik jihatdan to‘g‘ri gapir. Toshkent va adabiy o‘zbek nutqiga xos sodda iboralarni tanla. Ruscha yoki inglizcha gap tuzilishini o‘zbekchaga ko‘chirib qo‘yma; so‘zma-so‘z tarjima, sun’iy iboralar va keraksiz chet so‘zlardan qoch.
Bola bilan mehribon ustozdek, “sen” deb samimiy gaplash. “Barakalla”, “Keling, birga topamiz”, “Ajoyib fikr!” kabi tabiiy bolalarcha ruhlantiruvchi iboralarni me’yorida ishlat.
Matematika, o‘qish, yozish va ingliz tilini kichik bosqichlarda o‘rgat. Javoblar aniq, yoshga mos, quvnoq va odatda 2–4 qisqa gapdan iborat bo‘lsin. Ovoz chiqarib o‘qishga qulay, qisqa va ravon jumlalar tuz.
Javob yuborishdan oldin ichingda o‘zbekcha imlo, qo‘shimcha va gap tuzilishini tekshir. Bitta sodda savol bilan bolani fikrlashga unda; xatolarini muloyim tuzat va hech qachon uyaltirma.
Agar bola ingliz tilida javob yoki qo‘shiq so‘rasa, ingliz tilida javob ber. Qo‘shiq so‘rasa, 4–8 qatordan iborat, sodda, quvnoq va mutlaqo original inglizcha bolalar qo‘shig‘ini yarat; mavjud qo‘shiqlarning matnini ko‘chirma.
Shaxsiy ma’lumot, manzil, telefon, parol yoki maktab nomini so‘rama. Xavfli vaziyatlarda ishonchli kattaga murojaat qilishni ayt.
Tibbiy, moliyaviy yoki xavfli ko‘rsatmalar bermagin. O‘zingni sun’iy intellekt yordamchisi ekaningni yashirma.`;

app.get("/api/live-token", aiLimiter, async (_req, res, next) => {
  try {
    if (!liveAi) return res.status(503).json({ error: "AI Ustoz xizmati sozlanmagan." });
    const expireTime = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const newSessionExpireTime = new Date(Date.now() + 60 * 1000).toISOString();
    const token = await liveAi.authTokens.create({
      config: {
        uses: 1,
        expireTime,
        newSessionExpireTime,
        liveConnectConstraints: {
          model: LIVE_MODEL,
          config: {
            responseModalities: ["AUDIO"],
            inputAudioTranscription: {},
            outputAudioTranscription: {},
            realtimeInputConfig: { automaticActivityDetection: { disabled: true } },
            systemInstruction: tutorInstruction,
            sessionResumption: {},
            thinkingConfig: { thinkingLevel: "minimal" }
          }
        }
      }
    });
    res.set("Cache-Control", "no-store");
    res.json({ token: token.name, model: LIVE_MODEL });
  } catch (error) {
    console.error("AI Live token error:", error?.message || error);
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
      maxOutputTokens: 180
    });
    const answer = clean(response.output_text);
    if (!answer) return res.status(502).json({ error: "AI bo‘sh javob qaytardi. Yana urinib ko‘ring." });
    res.json({ answer });
  } catch (error) {
    const message = String(error?.message || "");
    if (/429|quota|resource_exhausted/i.test(message)) return res.status(429).json({ error: "AI savollari limiti vaqtincha tugadi. Birozdan keyin urinib ko‘ring." });
    console.error("AI tutor interaction error:", message);
    next(error);
  }
});
app.post("/api/ai/tutor", requireDb, auth, aiLimiter, async (req, res, next) => {
  try {
    if (!ai) return res.status(503).json({ error: "AI Ustoz xizmati sozlanmagan. Administrator AI kalitini tekshirishi kerak." });
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
      "SELECT role,message FROM ai_conversations WHERE child_id=$1 ORDER BY created_at DESC LIMIT 4",
      [childId]
    );
    const transcript = history.rows.reverse().map(row => (row.role === "user" ? "Bola: " : "Ustoz: ") + row.message).join("\n");
    const response = await generateTutorContent({
      input: `O‘quvchi: ${child.display_name}, yoshi: ${child.age}. Fan: ${subject}.\n${transcript ? "Oldingi suhbat:\n" + transcript + "\n" : ""}Bolaning yangi savoli: ${message}`,
      systemInstruction: tutorInstruction,
      temperature: 0.35,
      maxOutputTokens: 220
    });
    const answer = clean(response.output_text);
    if (!answer) throw new Error("AI Ustoz bo‘sh javob qaytardi.");
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
app.patch("/api/admin/users/:id", requireDb, auth, requireAdmin, async (req, res, next) => {
  try {
    const fullName = clean(req.body?.fullName);
    const childName = clean(req.body?.childName);
    const age = Number(req.body?.age);
    if (fullName.length < 2 || fullName.length > 100 || childName.length < 1 || childName.length > 40 || !Number.isInteger(age) || age < 5 || age > 12) {
      return res.status(400).json({ error: "Foydalanuvchi yoki bola ma’lumotlarini tekshiring." });
    }
    const updated = await pool.query("UPDATE parents SET full_name=$1 WHERE id=$2 RETURNING id,full_name,email", [fullName, req.params.id]);
    if (!updated.rowCount) return res.status(404).json({ error: "Foydalanuvchi topilmadi." });
    const child = await pool.query("UPDATE children SET display_name=$1,age=$2 WHERE parent_id=$3 AND id=(SELECT id FROM children WHERE parent_id=$3 ORDER BY created_at LIMIT 1) RETURNING id,display_name,age", [childName, age, req.params.id]);
    res.json({ user: updated.rows[0], child: child.rows[0] || null });
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
    if (!["lesson","image","game","video"].includes(kind) || title.length < 2 || title.length > 100 ||
        imageUrl.length > 1000 || (imageUrl && !imageUrl.startsWith("https://"))) {
      return res.status(400).json({ error: "Tur, sarlavha yoki HTTPS rasm havolasini tekshiring." });
    }
    if (kind === "video") {
      const videoUrl = clean(contentData.videoUrl);
      let parsedUrl;
      try { parsedUrl = new URL(videoUrl); } catch {}
      const host = parsedUrl?.hostname?.toLowerCase().replace(/^www\./, "");
      let videoId = "";
      if (host === "youtu.be") videoId = parsedUrl.pathname.split("/").filter(Boolean)[0] || "";
      if (host === "youtube.com" || host === "m.youtube.com" || host === "youtube-nocookie.com") {
        videoId = parsedUrl.searchParams.get("v") || parsedUrl.pathname.match(/\/(?:embed|shorts)\/([\w-]{11})/)?.[1] || "";
      }
      if (!/^[\w-]{11}$/.test(videoId)) return res.status(400).json({ error: "YouTube video havolasini to‘g‘ri kiriting." });
      contentData.videoId = videoId;
      delete contentData.videoUrl;
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
