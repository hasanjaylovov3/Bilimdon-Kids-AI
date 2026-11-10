# Bilimdon Kids AI

7–10 yoshli bolalar uchun o'zbek tilidagi AI ta'lim platformasi. Fanlar: matematika, o'qish, yozish va ingliz tili.

## Arxitektura
- **Frontend:** `public/` ichidagi web ilova (responsive, PWA asoslari).
- **Backend:** Node.js 20+ va Express 5.
- **AI:** Google Gemini SDK (`@google/genai`), standart model `gemini-2.5-flash`.
- **Database:** PostgreSQL.
- **Auth:** ota-ona hisobi, bcrypt parol xeshi, HttpOnly sessiya cookie.
- **Progress:** har bir bola profiliga bog'langan mashq natijalari.

## Lokal ishga tushirish
1. Node.js 20+ va PostgreSQL o'rnating.
2. `npm install`
3. `cp .env.example .env` va `DATABASE_URL`, `GEMINI_API_KEY` ni kiriting.
4. PostgreSQL bazasida `db/schema.sql` ni bajaring.
5. `npm start`
6. Brauzerda `http://localhost:3000` ni oching.

**Muhim:** Gemini API kalitini hech qachon frontend, HTML yoki GitHub commit ichiga joylamang. Faqat hosting provayderining server-side environment variables bo'limidan kiriting.

## Hosting
GitHub Pages faqat statik frontendni joylaydi; autentifikatsiya, Gemini va progress saqlash uchun Node.js backend hamda PostgreSQL kerak. Backendni Render, Railway yoki boshqa Node.js hostingga, bazani PostgreSQL hostingga joylashtiring. Hostingda `DATABASE_URL`, `GEMINI_API_KEY`, `NODE_ENV=production` va `APP_ORIGIN` ni sozlang.

## Android
PWA shell dastlabki bosqichda mavjud. Capacitor Android loyihasi va APK CI build keyingi bosqichda qo'shiladi; APK build uchun Android SDK/Gradle muhitiga ega CI runner kerak.

## Xavfsizlik
- Ota-ona email/paroli bilan ro'yxatdan o'tadi; bola alohida profil sifatida saqlanadi.
- Parollar bcrypt bilan xeshlanadi; sessiya tokenining faqat SHA-256 xeshi bazada saqlanadi.
- API endpointlarida input tekshiruvi va rate limit mavjud.
- AI javoblari yoshga mos tizim ko'rsatmasi bilan yaratiladi. Ishga tushirishdan oldin ota-ona nazorati, xavfsizlik sinovlari va deployment sozlamalarini tekshiring.

## Hozirgi holat
Birinchi bosqichda backend, Gemini API, ota-ona autentifikatsiyasi, bola profili, progress saqlash va asosiy fan mashqlari joylandi. Dastlabki yuklangan 3D HTML ilovadagi barcha animatsiyalar va interaktiv ekranlarni to'liq ko'chirish/ulash hali bajarilmagan; ular keyingi integratsiya bosqichida saqlanib ulanadi.
