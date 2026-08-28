import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { callGasApi, GAS_WEBAPP_URL } from './gasService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// Enable CORS and body parsers
app.disable('x-powered-by');

app.use(cors({
  origin: true,
  credentials: true
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ extended: true }));

// -------------------------------------------------------------
// ADMIN LOGIN FIX V4.5 / Robust Cookie + Bearer + Query Session Fallback
// Default credentials requested for this project:
// username: admin
// password: 1234
// For production, set ADMIN_USERNAME / ADMIN_PASSWORD as Secrets.
// -------------------------------------------------------------
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || 'admin').trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '1234').trim();

const ALLOW_PREVIEW_ADMIN_TOKEN = String(
  process.env.ALLOW_PREVIEW_ADMIN_TOKEN || 'true'
).toLowerCase() !== 'false';

const MEETING_RECORDS_API_URL = String(
  process.env.MEETING_RECORDS_API_URL || ''
).trim();

const MEETING_RECORDS_API_TOKEN = String(
  process.env.MEETING_RECORDS_API_TOKEN || ''
).trim();
const ADMIN_SESSION_MS = 8 * 60 * 60 * 1000; // 8 hours
const ADMIN_COOKIE = 'sm_admin_session';
const adminSessions = new Map();
const adminFailures = new Map();

const ADMIN_PROTECTED_PAGES = new Set([
  '/admin.html',
  '/meetings.html',
  '/dashboard.html',
  '/smart-room.html',
  '/config.html',
  '/register.html',
  '/scan.html',
  '/system-health.html'
]);

const ADMIN_POST_ACTIONS = new Set([
  'saveConfig',
  'createMeeting',
  'updateMeeting',
  'saveMeeting',
  'deleteMeeting',
  'approveRegistration',
  'rejectRegistration',
  'cancelRegistration',
  'finalizeMeetingAttendance',
  'registerUser',
  'deleteUserFace',
  'saveMeetingMinutes'
]);

const ADMIN_GET_ACTIONS = new Set([
  'getConfig'
]);

function parseCookies(req) {
  const out = {};
  const raw = String(req.headers.cookie || '');
  raw.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx <= 0) return;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    try { out[key] = decodeURIComponent(value); } catch { out[key] = value; }
  });
  return out;
}

function extractAdminToken(req) {
  // 1) Cookie (normal browser deployment)
  const cookieToken = parseCookies(req)[ADMIN_COOKIE];
  if (cookieToken) return cookieToken;

  // 2) Authorization: Bearer <token>
  // Required as a reliable fallback in Google AI Studio Preview.
  const auth = String(req.headers.authorization || '');
  const bearer = auth.match(/^Bearer\s+(.+)$/i);
  if (bearer && bearer[1]) return bearer[1].trim();

  // 3) Query parameter on protected admin pages.
  const queryToken = String(req.query?.admin_token || '').trim();
  if (queryToken) return queryToken;

  // 4) Same-origin Referer.
  // Admin sub-pages inherit the temporary token via Referer.
  const ref = String(req.headers.referer || '');
  if (ref) {
    try {
      const u = new URL(ref);
      const refToken = String(u.searchParams.get('admin_token') || '').trim();
      if (refToken) return refToken;
    } catch {}
  }

  return '';
}

function getAdminSession(req) {
  const token = extractAdminToken(req);
  if (!token) return null;

  const session = adminSessions.get(token);
  if (!session) return null;

  if (session.expiresAt <= Date.now()) {
    adminSessions.delete(token);
    return null;
  }

  return { token, ...session };
}

function isAdminAuthenticated(req) {
  return Boolean(getAdminSession(req));
}

function setAdminCookie(req, res, token) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '');
  const isHttps = req.secure || forwardedProto.includes('https');
  const secure = isHttps ? '; Secure' : '';

  res.setHeader(
    'Set-Cookie',
    `${ADMIN_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(ADMIN_SESSION_MS / 1000)}${secure}`
  );
}

function clearAdminCookie(req, res) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '');
  const isHttps = req.secure || forwardedProto.includes('https');
  const secure = isHttps ? '; Secure' : '';

  res.setHeader(
    'Set-Cookie',
    `${ADMIN_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`
  );
}

function safeTextEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function clientKey(req) {
  return String(
    req.headers['x-forwarded-for'] ||
    req.socket?.remoteAddress ||
    'unknown'
  ).split(',')[0].trim();
}

function registerFailedLogin(req) {
  const key = clientKey(req);
  const now = Date.now();
  const state = adminFailures.get(key) || { count: 0, firstAt: now, lockedUntil: 0 };

  if (now - state.firstAt > 10 * 60 * 1000) {
    state.count = 0;
    state.firstAt = now;
    state.lockedUntil = 0;
  }

  state.count += 1;

  if (state.count >= 5) {
    state.lockedUntil = now + 5 * 60 * 1000;
  }

  adminFailures.set(key, state);
  return state;
}

function checkLoginLock(req) {
  const state = adminFailures.get(clientKey(req));
  if (!state) return 0;

  const remaining = state.lockedUntil - Date.now();
  return remaining > 0 ? remaining : 0;
}

function requireAdminApi(req, res) {
  if (isAdminAuthenticated(req)) return true;

  res.status(401).json({
    success: false,
    code: 'ADMIN_LOGIN_REQUIRED',
    message: 'กรุณาเข้าสู่ระบบผู้ดูแลก่อนดำเนินการ'
  });

  return false;
}

// Custom login API
app.post('/api/admin/login', (req, res) => {
  const lockedMs = checkLoginLock(req);

  if (lockedMs > 0) {
    return res.status(429).json({
      success: false,
      message: `ใส่รหัสผิดหลายครั้ง กรุณารอประมาณ ${Math.ceil(lockedMs / 60000)} นาที`
    });
  }

  const username = String(req.body?.username || '');
  const password = String(req.body?.password || '');

  const ok = safeTextEqual(username, ADMIN_USERNAME) &&
    safeTextEqual(password, ADMIN_PASSWORD);

  if (!ok) {
    const state = registerFailedLogin(req);

    return res.status(401).json({
      success: false,
      message: state.lockedUntil > Date.now()
        ? 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง ระบบล็อกชั่วคราว 5 นาที'
        : 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
    });
  }

  adminFailures.delete(clientKey(req));

  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, {
    username: ADMIN_USERNAME,
    createdAt: Date.now(),
    expiresAt: Date.now() + ADMIN_SESSION_MS
  });

  setAdminCookie(req, res, token);

  return res.json({
    success: true,
    username: ADMIN_USERNAME,
    token,
    previewTokenAllowed: true,
    expiresInMinutes: Math.round(ADMIN_SESSION_MS / 60000)
  });
});

app.get('/api/admin/auth-status', (req, res) => {
  return res.json({
    success: true,
    usernameConfigured: Boolean(ADMIN_USERNAME),
    passwordConfigured: Boolean(ADMIN_PASSWORD),
    previewFallbackEnabled: true,
    sessionMinutes: Math.round(ADMIN_SESSION_MS / 60000)
  });
});

app.get('/api/admin/session', (req, res) => {
  const session = getAdminSession(req);

  return res.json({
    success: true,
    authenticated: Boolean(session),
    username: session?.username || null
  });
});

app.post('/api/admin/logout', (req, res) => {
  const session = getAdminSession(req);

  if (session?.token) {
    adminSessions.delete(session.token);
  }

  clearAdminCookie(req, res);

  return res.json({
    success: true,
    message: 'ออกจากระบบเรียบร้อย'
  });
});

// Protect admin HTML pages even if someone types the URL directly.
app.use((req, res, next) => {
  if (req.method !== 'GET') return next();

  const pathname = String(req.path || '').toLowerCase();

  if (!ADMIN_PROTECTED_PAGES.has(pathname)) {
    return next();
  }

  const session = getAdminSession(req);

  if (session) {
    const currentToken = String(req.query?.admin_token || '').trim();

    if (!currentToken) {
      const qs = new URLSearchParams(req.query || {});
      qs.set('admin_token', session.token);
      const suffix = qs.toString() ? `?${qs.toString()}` : '';
      return res.redirect(`${pathname}${suffix}`);
    }

    return next();
  }

  const nextUrl = encodeURIComponent(pathname.replace(/^\//, '') || 'admin.html');
  return res.redirect(`/admin-login.html?next=${nextUrl}`);
});




// -------------------------------------------------------------
// Production Records API Proxy
// Browser never receives Google Apps Script URL or Shared Token.
// -------------------------------------------------------------
async function callRecordsApi(action, payload = {}, method = 'GET', timeoutMs = 45000) {
  if (!MEETING_RECORDS_API_URL) {
    throw new Error('ยังไม่ได้ตั้ง Secret: MEETING_RECORDS_API_URL');
  }

  if (!MEETING_RECORDS_API_TOKEN) {
    throw new Error('ยังไม่ได้ตั้ง Secret: MEETING_RECORDS_API_TOKEN');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let response;

    if (String(method).toUpperCase() === 'GET') {
      const url = new URL(MEETING_RECORDS_API_URL);
      url.searchParams.set('action', action);
      url.searchParams.set('api_token', MEETING_RECORDS_API_TOKEN);

      Object.entries(payload || {}).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          url.searchParams.set(key, String(value));
        }
      });

      response = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal
      });
    } else {
      response = await fetch(MEETING_RECORDS_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
        body: JSON.stringify({
          action,
          api_token: MEETING_RECORDS_API_TOKEN,
          ...(payload || {})
        }),
        redirect: 'follow',
        signal: controller.signal
      });
    }

    const raw = await response.text();
    let data;

    try {
      data = raw ? JSON.parse(raw) : {};
    } catch {
      throw new Error(`Records API ตอบกลับไม่ใช่ JSON (HTTP ${response.status})`);
    }

    if (!response.ok || data.success !== true) {
      throw new Error(data.message || data.error || `Records API HTTP ${response.status}`);
    }

    return data;
  } finally {
    clearTimeout(timer);
  }
}

function recordsProxyConfigured() {
  return Boolean(MEETING_RECORDS_API_URL && MEETING_RECORDS_API_TOKEN);
}

app.get('/api/records/status', async (req, res) => {
  if (!recordsProxyConfigured()) {
    return res.status(503).json({
      success: false,
      configured: false,
      message: 'ยังไม่ได้ตั้ง MEETING_RECORDS_API_URL / MEETING_RECORDS_API_TOKEN'
    });
  }

  try {
    const check = await callRecordsApi('systemCheck');

    return res.json({
      success: true,
      configured: true,
      version: check.version,
      spreadsheet: check.spreadsheet,
      sheet: check.sheet,
      drive: check.drive,
      sheet_rows: check.sheet_rows
    });
  } catch (err) {
    return res.status(502).json({
      success: false,
      configured: true,
      message: err.message || String(err)
    });
  }
});

app.get('/api/records/list', async (req, res) => {
  try {
    const data = await callRecordsApi('listRecords');
    return res.json(data);
  } catch (err) {
    return res.status(502).json({
      success: false,
      message: err.message || String(err)
    });
  }
});

app.post('/api/records', async (req, res) => {
  const action = String(req.body?.action || '').trim();
  const allowed = new Set([
    'createRecord',
    'uploadAudio',
    'updateRecord',
    'generateReport'
  ]);

  if (!allowed.has(action)) {
    return res.status(400).json({
      success: false,
      message: 'Records action ไม่ได้รับอนุญาต'
    });
  }

  try {
    const payload = { ...(req.body || {}) };
    delete payload.action;
    delete payload.api_token;

    const data = await callRecordsApi(action, payload, 'POST', 120000);
    return res.json(data);
  } catch (err) {
    return res.status(502).json({
      success: false,
      message: err.message || String(err)
    });
  }
});


// Persistence file path
const DATA_FILE = path.join(__dirname, 'attendance_data.json');

// Default initial state
const defaultData = {
  gasWebAppUrl: GAS_WEBAPP_URL,
  gpsConfig: {
    lat: 13.8198,
    lng: 100.5144,
    radius: 500, // meters (e.g. KMUTNB / Office HQ)
    officeName: 'สำนักงานใหญ่ (KMUTNB HQ)'
  },
  knownFaces: [],
  attendanceLogs: [
    {
      id: 'att_1',
      name: 'สมชาย ใจดี (HR Lead)',
      time: '08:24:10',
      date: '26/8/2569',
      lat: 13.8199,
      lng: 100.5142,
      mapLink: 'https://www.google.com/maps?q=13.8199,100.5142',
      status: 'on_time',
      type: 'work_checkin',
      distance: 18,
      timestamp: '2026-08-26T08:24:10.000Z'
    },
    {
      id: 'att_2',
      name: 'วิภาดา รักเรียน (Tech Lead)',
      time: '08:45:30',
      date: '26/8/2569',
      lat: 13.8197,
      lng: 100.5145,
      mapLink: 'https://www.google.com/maps?q=13.8197,100.5145',
      status: 'on_time',
      type: 'work_checkin',
      distance: 15,
      timestamp: '2026-08-26T08:45:30.000Z'
    },
    {
      id: 'att_3',
      name: 'กิตติศักดิ์ พัฒนา (Product Manager)',
      time: '09:05:12',
      date: '26/8/2569',
      lat: 13.8201,
      lng: 100.5140,
      mapLink: 'https://www.google.com/maps?q=13.8201,100.5140',
      status: 'late',
      type: 'work_checkin',
      distance: 35,
      timestamp: '2026-08-26T09:05:12.000Z'
    }
  ],
  meetings: [
    {
      id: 'mtg_1',
      title: 'การประชุมวางแผนพัฒนาระบบ AI & Face Recognition Q3',
      agenda: '1. สรุปผลการทดสอบระบบ Face Scan & GPS\n2. การเชื่อมต่อ Gemini AI สำหรับถอดเสียงและสรุปการประชุม\n3. กำหนดการเปิดใช้งานระบบทั่วทั้งองค์กร',
      date: '2026-08-27',
      startTime: '09:30',
      endTime: '11:00',
      room: 'ห้องประชุมใหญ่ อาคาร 1 ชั้น 4 (Boardroom)',
      locationType: 'hybrid',
      gpsRequired: true,
      gpsLat: 13.8198,
      gpsLng: 100.5144,
      gpsRadius: 300,
      organizer: 'สมชาย ใจดี (HR Lead)',
      department: 'เทคโนโลยีและวิศวกรรม (Tech)',
      participants: ['สมชาย ใจดี (HR Lead)', 'วิภาดา รักเรียน (Tech Lead)', 'กิตติศักดิ์ พัฒนา (Product Manager)', 'ณิชาภา สุขสมบัติ (Designer)'],
      status: 'scheduled',
      transcript: '00:01 [สมชาย]: สวัสดีครับทุกท่าน วันนี้เราประชุมเรื่องแผนพัฒนาฟีเจอร์ AI Transcript และ Face Attendance\n00:45 [วิภาดา]: ระบบ Face Scan ตรวจจับได้แม่นยำ 98.5% และความเร็วในการจำแนกใบหน้าต่ำกว่า 200ms\n01:30 [กิตติศักดิ์]: ฝั่ง Product เสนอให้เพิ่มระบบสรุปการประชุม AI ด้วย Gemini เพื่อสร้าง Action Items อัตโนมัติ\n02:15 [ณิชาภา]: ออกแบบหน้า UI ใหม่เรียบร้อยแล้ว รองรับทั้ง Desktop, Tablet และ Mobile เต็มรูปแบบ\n03:00 [สมชาย]: สรุปมติอนุมัติ Deploy เวอร์ชัน v1-v7 ภายในสัปดาห์นี้ครับ',
      aiSummary: {
        executiveSummary: 'การประชุมเพื่อวางแผนการเปิดตัวระบบ Face Recognition & GPS ร่วมกับฟังก์ชัน AI Transcription และ Smart Meeting Assistant ผลการทดสอบโมเดลมีความแม่นยำสูงและพร้อมขยายผลใช้งานจริง',
        keyPoints: [
          'ระบบตรวจจับใบหน้ามีความแม่นยำ 98.5% พร้อมระบบยืนยันพิกัด GPS อัตโนมัติ',
          'เพิ่มฟังก์ชันบันทึกเสียงและถอดเสียงภาษาไทย/อังกฤษแบบเรียลไทม์',
          'ผสานพลัง Gemini AI สรุปสาระสำคัญและสร้าง Action Items โดยอัตโนมัติ'
        ],
        decisions: [
          'อนุมัติเปิดใช้งานระบบเวอร์ชันเต็ม (v1-v7) ทั่วทั้งองค์กร',
          'กำหนดให้อุปกรณ์หน้าห้องประชุมทุกห้องติดตั้งหน้าจอสำหรับสแกนใบหน้าเข้าประชุม'
        ],
        actionItems: [
          { task: 'ปรับแต่ง UI Responsive และทดสอบระบบเสียงในห้องประชุม', assignee: 'ณิชาภา สุขสมบัติ (Designer)', deadline: '2026-08-28', priority: 'High', status: 'In Progress' },
          { task: 'เชื่อมต่อ Gemini API endpoint สรุปเนื้อหาและถอดความภาษาไทย', assignee: 'วิภาดา รักเรียน (Tech Lead)', deadline: '2026-08-29', priority: 'High', status: 'Completed' },
          { task: 'จัดอบรมการใช้งานระบบสำหรับพนักงานทุกแผนก', assignee: 'สมชาย ใจดี (HR Lead)', deadline: '2026-08-30', priority: 'Medium', status: 'Pending' }
        ],
        sentiment: 'บรรยากาศเป็นไปในเชิงบวก ทีมงานมีความพร้อมสูงและเห็นพ้องต้องกันในทิศทางการพัฒนานวัตกรรมองค์กร',
        nextMeeting: 'ติดตามผลการใช้งานวันที่ 3 กันยายน 2569 เวลา 10:00 น.'
      },
      createdAt: '2026-08-25T10:00:00.000Z'
    },
    {
      id: 'mtg_2',
      title: 'Weekly Standup & Sprint Review',
      agenda: '1. อัปเดตงานประจำสัปดาห์\n2. ปัญหาและอุปสรรค (Blockers)\n3. เป้าหมาย Sprint ถัดไป',
      date: '2026-08-26',
      startTime: '13:30',
      endTime: '14:30',
      room: 'Online Meeting Room A',
      locationType: 'online',
      gpsRequired: false,
      gpsLat: 0,
      gpsLng: 0,
      gpsRadius: 0,
      organizer: 'กิตติศักดิ์ พัฒนา (Product Manager)',
      department: 'ผลิตภัณฑ์ (Product)',
      participants: ['วิภาดา รักเรียน (Tech Lead)', 'กิตติศักดิ์ พัฒนา (Product Manager)', 'ณิชาภา สุขสมบัติ (Designer)', 'ธนากร มุ่งมั่น (Marketing)'],
      status: 'completed',
      transcript: '00:05 [กิตติศักดิ์]: เริ่ม Standup ประจำสัปดาห์ครับ\n00:40 [วิภาดา]: ฝั่ง Dev เสร็จสิ้นการทำ Backend API และเชื่อมต่อ AI Service\n01:20 [ธนากร]: Marketing เตรียมทำคู่มือและการสื่อสารเปิดตัวระบบแล้วครับ',
      aiSummary: {
        executiveSummary: 'การประชุมติดตามความคืบหน้ารอบสัปดาห์ ทุกฝ่ายส่งมอบงานตามแผน และไม่มีอุปสรรคสำคัญ',
        keyPoints: [
          'การพัฒนา Backend และ API เสร็จสมบูรณ์',
          'สื่อประชาสัมพันธ์และคู่มือการใช้งานพร้อมเผยแพร่'
        ],
        decisions: [
          'เดินหน้าเปิดตัวตามกำหนดการเดิม'
        ],
        actionItems: [
          { task: 'ส่งมอบ Release Notes และคู่มือระบบ', assignee: 'ธนากร มุ่งมั่น (Marketing)', deadline: '2026-08-27', priority: 'Medium', status: 'Completed' }
        ],
        sentiment: 'กระตือรือร้นและตรงตามเป้าหมาย',
        nextMeeting: 'วันจันทร์หน้า 13:30 น.'
      },
      createdAt: '2026-08-24T08:00:00.000Z'
    }
  ],
  meetingAttendance: [
    {
      id: 'matt_1',
      meetingId: 'mtg_1',
      participantName: 'สมชาย ใจดี (HR Lead)',
      checkInTime: '09:25:40',
      checkInDate: '27/8/2569',
      status: 'on_time',
      lat: 13.8198,
      lng: 100.5144,
      distance: 5,
      confidence: 0.98,
      timestamp: '2026-08-27T09:25:40.000Z'
    },
    {
      id: 'matt_2',
      meetingId: 'mtg_1',
      participantName: 'วิภาดา รักเรียน (Tech Lead)',
      checkInTime: '09:28:15',
      checkInDate: '27/8/2569',
      status: 'on_time',
      lat: 13.8197,
      lng: 100.5143,
      distance: 12,
      confidence: 0.96,
      timestamp: '2026-08-27T09:28:15.000Z'
    },
    {
      id: 'matt_3',
      meetingId: 'mtg_1',
      participantName: 'กิตติศักดิ์ พัฒนา (Product Manager)',
      checkInTime: '09:38:00',
      checkInDate: '27/8/2569',
      status: 'late',
      lat: 13.8199,
      lng: 100.5146,
      distance: 22,
      confidence: 0.94,
      timestamp: '2026-08-27T09:38:00.000Z'
    }
  ]
};

// In-memory data store with file persistence
let store = { ...defaultData };

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf-8');
      const parsed = JSON.parse(raw);
      store = {
        ...defaultData,
        ...parsed,
        gpsConfig: { ...defaultData.gpsConfig, ...(parsed.gpsConfig || {}) },
        knownFaces: parsed.knownFaces || defaultData.knownFaces,
        attendanceLogs: parsed.attendanceLogs || defaultData.attendanceLogs,
        meetings: parsed.meetings || defaultData.meetings,
        meetingAttendance: parsed.meetingAttendance || defaultData.meetingAttendance
      };
      console.log(`[Store] Loaded data from ${DATA_FILE}`);
    } else {
      saveData();
    }
  } catch (err) {
    console.error('[Store] Error loading data:', err.message);
  }
}

function saveData() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2), 'utf-8');
  } catch (err) {
    console.error('[Store] Error saving data:', err.message);
  }
}

loadData();

function getCurrentGasUrl() {
  return (store.gasWebAppUrl || GAS_WEBAPP_URL || '').trim();
}

async function callCurrentGasApi(action, params = {}, method = 'GET', timeoutMs = 15000) {
  return callGasApi(action, params, method, timeoutMs, getCurrentGasUrl());
}

// Helper: Calculate distance in meters
function getDistanceMeters(lat1, lon1, lat2, lon2) {
  if (!lat1 || !lon1 || !lat2 || !lon2) return 0;
  const R = 6371e3; // Earth radius in metres
  const φ1 = (lat1 * Math.PI) / 180;
  const φ2 = (lat2 * Math.PI) / 180;
  const Δφ = ((lat2 - lat1) * Math.PI) / 180;
  const Δλ = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return Math.round(R * c);
}


// -------------------------------------------------------------
// Registration Source-of-Truth Helpers — V4.12
// Google Sheets / GAS is authoritative.
// -------------------------------------------------------------
function firstRegValue(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      return value;
    }
  }
  return '';
}

function normalizeRegistrationRow(row = {}) {
  const participantType = String(
    firstRegValue(
      row.participant_type,
      row.participantType,
      row.type,
      row.participant_category
    ) || (row.employee_code || row.employeeCode ? 'INTERNAL' : 'EXTERNAL')
  ).trim().toUpperCase();

  const fullname = String(firstRegValue(
    row.fullname,
    row.full_name,
    row.name,
    row.participant_name,
    row.name_th,
    row.fullname_th
  )).trim();

  const fullnameEn = String(firstRegValue(
    row.fullname_en,
    row.fullname_english,
    row.name_en,
    row.english_name,
    row.name_english
  )).trim();

  const affiliation = String(firstRegValue(
    row.affiliation,
    row.organization,
    row.organisation,
    row.department,
    row.org,
    row.company,
    row.institution
  )).trim();

  const department = String(firstRegValue(
    row.department,
    participantType === 'INTERNAL' ? affiliation : ''
  )).trim();

  const organization = String(firstRegValue(
    row.organization,
    row.organisation,
    participantType === 'EXTERNAL' ? affiliation : ''
  )).trim();

  return {
    ...row,
    registration_id: String(firstRegValue(row.registration_id, row.registrationId, row.id)).trim(),
    meeting_id: String(firstRegValue(row.meeting_id, row.meetingId)).trim(),
    participant_type: participantType,
    fullname,
    fullname_en: fullnameEn,
    employee_code: String(firstRegValue(row.employee_code, row.employeeCode)).trim(),
    affiliation: affiliation || organization || department,
    organization,
    department,
    position: String(firstRegValue(row.position, row.job_title, row.role)).trim(),
    email: String(firstRegValue(row.email, row.email_address)).trim(),
    phone: String(firstRegValue(row.phone, row.telephone, row.mobile)).trim(),
    approval_status: String(firstRegValue(
      row.approval_status,
      row.registration_status,
      row.status,
      'PENDING'
    )).trim().toUpperCase(),
    registered_at: firstRegValue(row.registered_at, row.created_at, row.timestamp, row.registration_date),
    descriptor: firstRegValue(row.descriptor, row.face_descriptor, row.faceDescriptor),
    face_descriptor: firstRegValue(row.face_descriptor, row.descriptor, row.faceDescriptor)
  };
}

function normalizeRegText(value) {
  return String(value ?? '').trim().toLowerCase();
}

function enrichRegistrationRowsFromLocal(rows) {
  // Google Sheets remains authoritative for row existence/status.
  // Local mirror may only fill display metadata omitted by an older GAS schema.
  const localRows = Array.isArray(store?.registrations) ? store.registrations : [];

  return rows.map(raw => {
    const row = normalizeRegistrationRow(raw);

    const local = localRows.find(item => {
      const a = normalizeRegistrationRow(item);

      if (row.registration_id && a.registration_id) {
        return row.registration_id === a.registration_id;
      }

      return (
        row.meeting_id === a.meeting_id &&
        row.email &&
        a.email &&
        normalizeRegText(row.email) === normalizeRegText(a.email)
      );
    });

    if (!local) return row;

    const localNorm = normalizeRegistrationRow(local);

    return normalizeRegistrationRow({
      ...localNorm,
      ...row,

      // Authoritative Sheet identity/status wins.
      registration_id: row.registration_id,
      meeting_id: row.meeting_id,
      approval_status: row.approval_status,

      // Fill missing metadata only.
      fullname_en: row.fullname_en || localNorm.fullname_en,
      affiliation: row.affiliation || localNorm.affiliation,
      organization: row.organization || localNorm.organization,
      department: row.department || localNorm.department,
      position: row.position || localNorm.position,
      email: row.email || localNorm.email,
      phone: row.phone || localNorm.phone,
      descriptor: row.descriptor || localNorm.descriptor,
      face_descriptor: row.face_descriptor || localNorm.face_descriptor
    });
  });
}

function extractRegistrationListFromGasResult(gasRes) {
  if (!gasRes || gasRes.success !== true) return null;

  const upstream = gasRes.data;
  let rows = null;

  if (Array.isArray(upstream)) {
    rows = upstream;
  } else if (upstream && typeof upstream === 'object') {
    if (upstream.success === false) return null;
    if (Array.isArray(upstream.data)) rows = upstream.data;
    else if (Array.isArray(upstream.registrations)) rows = upstream.registrations;
  }

  if (!rows) return null;

  return enrichRegistrationRowsFromLocal(
    rows.map(normalizeRegistrationRow)
  );
}

function registrationMatchesPayload(row, payload) {
  const a = normalizeRegistrationRow(row);
  const b = normalizeRegistrationRow(payload);

  if (normalizeRegText(a.meeting_id) !== normalizeRegText(b.meeting_id)) {
    return false;
  }

  const pairs = [
    [a.registration_id, b.registration_id],
    [a.email, b.email],
    [a.employee_code, b.employee_code],
    [a.fullname, b.fullname],
    [a.fullname_en, b.fullname_en]
  ];

  return pairs.some(([x, y]) => {
    const nx = normalizeRegText(x);
    const ny = normalizeRegText(y);
    return nx && ny && nx === ny;
  });
}

async function verifyRegistrationInSheets(payload, preferredRegistrationId = '') {
  // V4.14: read-after-write is useful, but it must NOT freeze the registration page.
  // One short check only. If Sheets propagation is delayed, the GAS write result
  // remains authoritative and Admin can load the record on the next refresh.
  try {
    const gasRes = await callCurrentGasApi(
      'getRegistrations',
      { meeting_id: payload.meeting_id },
      'GET',
      5000
    );

    const rows = extractRegistrationListFromGasResult(gasRes);

    if (!rows) return null;

    let found = null;

    if (preferredRegistrationId) {
      found = rows.find(
        r => normalizeRegText(r?.registration_id) === normalizeRegText(preferredRegistrationId)
      );
    }

    if (!found) {
      found = rows.find(r => registrationMatchesPayload(r, payload));
    }

    return found || null;
  } catch (e) {
    console.warn('[Registration Verify] Best-effort read-back failed:', e.message);
    return null;
  }
}

// -------------------------------------------------------------
// REST API Endpoints
// -------------------------------------------------------------

// System Health & Connection Endpoints (Google Apps Script & Google Sheets)
app.get('/api/system/health', async (req, res) => {
  try {
    const gasResult = await callCurrentGasApi('ping');
    if (gasResult.success && gasResult.data && gasResult.data.success === true) {
      return res.json({
        success: true,
        status: 'Online',
        gasConnected: true,
        gasUrl: getCurrentGasUrl(),
        message: gasResult.data?.message || 'Smart Meeting API is working',
        raw: gasResult.data,
        timestamp: new Date().toISOString()
      });
    } else {
      return res.status(502).json({
        success: false,
        status: 'Offline',
        gasConnected: false,
        gasUrl: getCurrentGasUrl(),
        error: gasResult.error || 'Failed to ping Google Apps Script',
        code: gasResult.code,
        timestamp: new Date().toISOString()
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      status: 'Offline',
      gasConnected: false,
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.get('/api/system/sheets', async (req, res) => {
  try {
    const gasResult = await callCurrentGasApi('listSheets');
    if (gasResult.success) {
      return res.json({
        success: true,
        status: 'Connected',
        sheetsConnected: true,
        sheets: gasResult.data?.sheets || gasResult.data || [],
        raw: gasResult.data,
        timestamp: new Date().toISOString()
      });
    } else {
      return res.status(502).json({
        success: false,
        status: 'Error',
        sheetsConnected: false,
        error: gasResult.error || 'Failed to list sheets from Google Apps Script',
        code: gasResult.code,
        timestamp: new Date().toISOString()
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      status: 'Error',
      sheetsConnected: false,
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Compatibility endpoint with legacy code.gs GET
app.get('/api', async (req, res) => {
  const action = req.query.action;

  if (ADMIN_GET_ACTIONS.has(action) && !requireAdminApi(req, res)) {
    return;
  }

  if (action === 'getConfig') {
    return res.json(store.gpsConfig);
  }
  if (action === 'getKnownFaces') {
    try {
      const requestedMeetingId = String(req.query.meeting_id || '').trim();

      function unwrapList(payload) {
        if (Array.isArray(payload)) return payload;
        if (payload && Array.isArray(payload.data)) return payload.data;
        if (payload && Array.isArray(payload.faces)) return payload.faces;
        if (payload && Array.isArray(payload.knownFaces)) return payload.knownFaces;
        return [];
      }

      function normalizeDescriptor(value) {
        if (!value) return null;
        if (Array.isArray(value)) {
          const arr = value.map(Number);
          return arr.length === 128 && arr.every(Number.isFinite) ? arr : null;
        }
        if (typeof value === 'string') {
          const text = value.trim();
          let arr = null;
          try {
            const parsed = JSON.parse(text);
            if (Array.isArray(parsed)) arr = parsed;
          } catch {}
          if (!arr && text.includes(',')) {
            arr = text.replace(/^\[/, '').replace(/\]$/, '').split(',').map(v => Number(v.trim()));
          }
          if (Array.isArray(arr)) {
            const nums = arr.map(Number);
            return nums.length === 128 && nums.every(Number.isFinite) ? nums : null;
          }
        }
        if (typeof value === 'object' && value !== null) {
          const keys = Object.keys(value).filter(k => /^\d+$/.test(k)).sort((a,b)=>Number(a)-Number(b));
          if (keys.length === 128) {
            const arr = keys.map(k => Number(value[k]));
            return arr.every(Number.isFinite) ? arr : null;
          }
        }
        return null;
      }

      const merged = [];

      // 1) Permanent/global face database (Users/Fig).
      try {
        const gasFaces = await callCurrentGasApi('getKnownFaces', req.query);
        if (gasFaces.success && gasFaces.data && gasFaces.data.success !== false) {
          unwrapList(gasFaces.data).forEach((item, index) => {
            const descriptor = normalizeDescriptor(item.descriptor || item.faceDescriptor || item.face_descriptor);
            if (!descriptor) return;
            let label = String(item.label || item.fullname || item.name || '').trim();
            let empCode = String(item.employee_code || item.employeeCode || item.id || '').trim();
            let fullname = String(item.fullname || item.name || label || '').trim();
            if (!empCode && label.includes(' - ')) {
              const parts = label.split(' - ');
              empCode = parts[0].trim();
              fullname = parts.slice(1).join(' - ').trim();
            }
            merged.push({
              id: item.id || (empCode ? `emp_${empCode}` : `global_${index}`),
              employee_code: empCode,
              label: label || (empCode ? `${empCode} - ${fullname}` : fullname),
              fullname,
              name: fullname,
              descriptor,
              participant_type: item.participant_type || 'INTERNAL',
              source: 'GLOBAL_FACE_DB'
            });
          });
        }
      } catch (e) {
        console.warn('[Faces] global getKnownFaces failed:', e.message);
      }

      // 2) Approved meeting registrations (especially EXTERNAL participants).
      let registrationRows = [];
      for (const gasAction of ['getRegistrations', 'getRegisteredParticipants']) {
        try {
          const gasRes = await callCurrentGasApi(
            gasAction,
            requestedMeetingId ? { meeting_id: requestedMeetingId } : {}
          );
          if (gasRes.success && gasRes.data) registrationRows.push(...unwrapList(gasRes.data));
        } catch (e) {
          console.warn(`[Faces] ${gasAction} failed:`, e.message);
        }
      }
      if (Array.isArray(store.registrations)) registrationRows.push(...store.registrations);

      registrationRows.forEach((rawReg, index) => {
        const reg = normalizeRegistrationRow(rawReg);
        const status = String(reg.approval_status || '').trim().toUpperCase();
        if (!['APPROVED', 'อนุมัติ'].includes(status)) return;

        const meetingId = String(reg.meeting_id || reg.meetingId || '').trim();
        if (requestedMeetingId && meetingId && meetingId !== requestedMeetingId) return;

        const descriptor = normalizeDescriptor(reg.descriptor || reg.face_descriptor || reg.faceDescriptor);
        if (!descriptor) return;

        const fullname = String(reg.fullname || reg.fullname_en || '').trim();
        const fullnameEn = String(reg.fullname_en || '').trim();
        if (!fullname) return;

        const employeeCode = String(reg.employee_code || '').trim();
        const participantType = String(reg.participant_type || reg.participantType || (employeeCode ? 'INTERNAL' : 'EXTERNAL')).trim().toUpperCase();
        const registrationId = String(reg.registration_id || reg.registrationId || `REG_FACE_${index}`).trim();
        const label = employeeCode ? `REG_EMP:${employeeCode}:${registrationId}` : `REG_EXT:${registrationId}`;

        merged.push({
          id: registrationId,
          registration_id: registrationId,
          meeting_id: meetingId,
          employee_code: employeeCode,
          label,
          fullname,
          fullname_en: fullnameEn,
          name: fullname,
          descriptor,
          participant_type: participantType,
          source: 'APPROVED_REGISTRATION'
        });
      });

      const seen = new Set();
      const finalList = merged.filter(item => {
        const sig = [item.label, item.meeting_id || '', item.descriptor.slice(0,6).map(v=>Number(v).toFixed(5)).join(',')].join('|');
        if (seen.has(sig)) return false;
        seen.add(sig);
        return true;
      });

      console.log(`[Faces] returned=${finalList.length} meeting=${requestedMeetingId || 'ALL'} approvedExternal=${finalList.filter(x => x.source === 'APPROVED_REGISTRATION' && x.participant_type === 'EXTERNAL').length}`);
      return res.json(finalList);
    } catch (e) {
      return res.status(502).json({ success:false, message:'โหลดฐานข้อมูลใบหน้าไม่สำเร็จ: ' + e.message });
    }
  }
  if (action === 'getAttendanceLogs') {
    return res.json(store.attendanceLogs);
  }
  if (action === 'getMeetings') {
    // Fetch directly from Google Apps Script first
    try {
      const gasRes = await callCurrentGasApi('getMeetings', req.query);
      if (gasRes.success && gasRes.data) {
        const meetings = Array.isArray(gasRes.data) ? gasRes.data : (Array.isArray(gasRes.data.data) ? gasRes.data.data : null);
        if (meetings) {
          return res.json(meetings);
        }
        return res.json(gasRes.data);
      }
    } catch (e) {
      console.warn('Fallback to local meetings store:', e.message);
    }
    return res.json(store.meetings);
  }
  if (action === 'getMeetingAttendance') {
    const meetingId = req.query.meeting_id || req.query.meetingId;
    try {
      const gasRes = await callCurrentGasApi('getMeetingAttendance', req.query);
      if (gasRes.success && gasRes.data) {
        const list = Array.isArray(gasRes.data) ? gasRes.data : (Array.isArray(gasRes.data.data) ? gasRes.data.data : null);
        if (list) {
          return res.json(list);
        }
        return res.json(gasRes.data);
      }
    } catch (e) {
      console.warn('Fallback getMeetingAttendance:', e.message);
    }
    const attList = store.meetingAttendance || [];
    if (meetingId) {
      return res.json(attList.filter(a => (a.meeting_id === meetingId || a.meetingId === meetingId)));
    }
    return res.json(attList);
  }
  if (action === 'getAttendanceSummary') {
    const meetingId = req.query.meeting_id || req.query.meetingId;
    try {
      const gasRes = await callCurrentGasApi('getAttendanceSummary', req.query);
      if (gasRes.success && gasRes.data) {
        if (gasRes.data.success !== false) {
          const sData = gasRes.data.data || gasRes.data;
          if (sData && typeof sData === 'object') {
            return res.json(sData);
          }
        }
      }
    } catch (e) {
      console.warn('Fallback getAttendanceSummary:', e.message);
    }

    // Local fallback calculation
    const allRegs = (store.registrations || []).filter(r => (r.meeting_id === meetingId || !meetingId));
    const approvedRegs = allRegs.filter(r => (r.approval_status || '').toUpperCase() === 'APPROVED');
    const attList = (store.meetingAttendance || []).filter(a => (a.meeting_id === meetingId || a.meetingId === meetingId || !meetingId));

    const totalApproved = approvedRegs.length;
    const checkedIn = attList.filter(a => a.check_in_time || a.checkInTime).length;
    const checkedOut = attList.filter(a => a.check_out_time || a.checkOutTime).length;
    const onTime = attList.filter(a => (a.check_in_status || a.status || '').toUpperCase() === 'ON_TIME' || a.status === 'on_time').length;
    const late = attList.filter(a => (a.check_in_status || a.status || '').toUpperCase() === 'LATE' || a.status === 'late').length;
    const lateCritical = attList.filter(a => (a.check_in_status || '').toUpperCase() === 'LATE_CRITICAL').length;
    const earlyLeave = attList.filter(a => (a.final_status || '').toUpperCase() === 'EARLY_LEAVE').length;
    const incomplete = attList.filter(a => (a.final_status || '').toUpperCase() === 'INCOMPLETE').length;
    const completed = attList.filter(a => (a.final_status || '').toUpperCase() === 'COMPLETED').length;
    const absent = Math.max(0, totalApproved - checkedIn) + attList.filter(a => (a.final_status || '').toUpperCase() === 'ABSENT').length;

    return res.json({
      success: true,
      total_approved: totalApproved,
      checked_in: checkedIn,
      checked_out: checkedOut,
      on_time: onTime,
      late: late,
      late_critical: lateCritical,
      early_leave: earlyLeave,
      incomplete: incomplete,
      completed: completed,
      absent: absent
    });
  }
  if (action === 'getRegistrations') {
    try {
      const gasRes = await callCurrentGasApi('getRegistrations', req.query);
      const regs = extractRegistrationListFromGasResult(gasRes);

      if (!regs) {
        const upstreamMessage =
          gasRes?.data?.message ||
          gasRes?.data?.error ||
          gasRes?.error ||
          'Google Sheets ไม่ได้ส่งรายการลงทะเบียนกลับมา';

        return res.status(502).json({
          success: false,
          code: 'REGISTRATIONS_SOURCE_UNAVAILABLE',
          message: upstreamMessage
        });
      }

      return res.json(regs);
    } catch (e) {
      return res.status(502).json({
        success: false,
        code: 'REGISTRATIONS_SOURCE_UNAVAILABLE',
        message: `โหลดคำขอลงทะเบียนจาก Google Sheets ไม่สำเร็จ: ${e.message}`
      });
    }
  }

  if (action === 'getRegistrationSummary') {
    try {
      const gasRes = await callCurrentGasApi('getRegistrations', req.query);
      const regs = extractRegistrationListFromGasResult(gasRes);

      if (!regs) {
        return res.status(502).json({
          success: false,
          code: 'REGISTRATION_SUMMARY_SOURCE_UNAVAILABLE',
          message: gasRes?.data?.message || gasRes?.error || 'โหลดข้อมูลจาก Google Sheets ไม่สำเร็จ'
        });
      }

      const meetingId = String(req.query.meeting_id || '').trim();
      const rows = meetingId
        ? regs.filter(r => String(r.meeting_id || '').trim() === meetingId)
        : regs;

      const statusOf = r =>
        String(r.approval_status || r.status || 'PENDING').trim().toUpperCase();

      return res.json({
        total: rows.length,
        pending: rows.filter(r => statusOf(r) === 'PENDING').length,
        approved: rows.filter(r => statusOf(r) === 'APPROVED').length,
        rejected: rows.filter(r => statusOf(r) === 'REJECTED').length,
        cancelled: rows.filter(r => statusOf(r) === 'CANCELLED').length
      });
    } catch (e) {
      return res.status(502).json({
        success: false,
        code: 'REGISTRATION_SUMMARY_SOURCE_UNAVAILABLE',
        message: `สรุปคำขอลงทะเบียนจาก Google Sheets ไม่สำเร็จ: ${e.message}`
      });
    }
  }

  if (action === 'getRegisteredParticipants') {
    try {
      const gasRes = await callCurrentGasApi('getRegisteredParticipants', req.query);
      if (gasRes.success && gasRes.data) {
        const parts = Array.isArray(gasRes.data) ? gasRes.data : (Array.isArray(gasRes.data.data) ? gasRes.data.data : null);
        if (parts) {
          return res.json(
            enrichRegistrationRowsFromLocal(parts.map(normalizeRegistrationRow))
          );
        }
        return res.json(gasRes.data);
      }
    } catch (e) {
      console.warn('Fallback registered participants:', e.message);
    }
    const regs = (store.registrations || []).filter(r => (r.approval_status || '').toUpperCase() === 'APPROVED');
    return res.json(regs);
  }
  if (action === 'getDashboardStats') {
    return res.json(getDashboardStats());
  }
  return res.json({ error: 'Unknown action: ' + action });
});

// Compatibility endpoint with legacy code.gs POST
app.post('/api', async (req, res) => {
  const data = typeof req.body === 'object' && req.body !== null ? req.body : {};
  const action = data.action;

  if (ADMIN_POST_ACTIONS.has(action) && !requireAdminApi(req, res)) {
    return;
  }

  // Step 4 Meeting Registration — V4.14 non-blocking GAS-confirmed flow
  if (action === 'registerMeeting') {
    try {
      if (!data.meeting_id || !data.fullname || !data.email) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_REGISTRATION_DATA',
          message: 'ข้อมูลลงทะเบียนไม่ครบ กรุณาตรวจสอบการประชุม ชื่อ และอีเมล'
        });
      }

      const gasRes = await callCurrentGasApi('registerMeeting', data, 'POST');

      if (!gasRes || gasRes.success !== true) {
        return res.status(502).json({
          success: false,
          code: 'REGISTRATION_GAS_CONNECTION_FAILED',
          message: gasRes?.error || 'ไม่สามารถเชื่อมต่อระบบ Google Sheets ได้'
        });
      }

      const upstream = gasRes.data;

      if (!upstream || upstream.success !== true) {
        return res.status(400).json({
          success: false,
          code: 'REGISTRATION_NOT_SAVED',
          message:
            upstream?.message ||
            upstream?.error ||
            'Google Sheets ปฏิเสธการบันทึกคำขอลงทะเบียน'
        });
      }

      // GAS returned success:true. This is the authoritative write result.
      // Read-back is only a short best-effort confirmation so the UI never hangs.
      const preferredId = String(
        upstream.registration_id ||
        upstream?.data?.registration_id ||
        upstream?.registration?.registration_id ||
        upstream.id ||
        ''
      ).trim();

      const sheetRow = await verifyRegistrationInSheets(data, preferredId);

      const actualRegistrationId = String(
        sheetRow?.registration_id ||
        preferredId ||
        ''
      ).trim();

      // If GAS confirmed success but returned no ID, try to use the row found by
      // the short read-back. If still unavailable, return a clear error quickly.
      if (!actualRegistrationId) {
        return res.status(502).json({
          success: false,
          code: 'REGISTRATION_ID_MISSING',
          message:
            'Google Sheets รับคำขอแล้ว แต่ยังไม่ส่งรหัสลงทะเบียนกลับมา กรุณารอสักครู่แล้วลองใหม่'
        });
      }

      // Local cache may mirror the Sheet for diagnostics only.
      // It is NOT used as the Admin source of truth.
      if (!store.registrations) store.registrations = [];

      const existingIndex = store.registrations.findIndex(
        r => String(r.registration_id || '').trim() === actualRegistrationId
      );

      const regObj = {
        ...(sheetRow || {}),
        registration_id: actualRegistrationId,
        meeting_id: data.meeting_id,
        participant_type: data.participant_type || sheetRow?.participant_type || 'INTERNAL',
        fullname: data.fullname,
        fullname_en:
          data.fullname_en ||
          data.name_en ||
          data.english_name ||
          sheetRow?.fullname_en ||
          '',
        employee_code: data.employee_code || '',
        affiliation:
          data.affiliation ||
          data.organization ||
          data.department ||
          sheetRow?.affiliation ||
          '',
        organization:
          data.organization ||
          (String(data.participant_type || '').toUpperCase() === 'EXTERNAL'
            ? (data.affiliation || data.department || '')
            : '') ||
          sheetRow?.organization ||
          '',
        department:
          data.department ||
          (String(data.participant_type || '').toUpperCase() === 'INTERNAL'
            ? (data.affiliation || data.organization || '')
            : '') ||
          sheetRow?.department ||
          '',
        position: data.position || sheetRow?.position || '',
        email: data.email || '',
        phone: data.phone || '',
        descriptor: Array.isArray(data.descriptor) ? data.descriptor : [],
        face_descriptor: Array.isArray(data.descriptor) ? data.descriptor : [],
        approval_status:
          sheetRow?.approval_status ||
          sheetRow?.status ||
          upstream.approval_status ||
          'PENDING',
        registered_at:
          sheetRow?.registered_at ||
          sheetRow?.created_at ||
          new Date().toISOString()
      };

      if (existingIndex >= 0) {
        store.registrations[existingIndex] = regObj;
      } else {
        store.registrations.unshift(regObj);
      }

      saveData();

      return res.json({
        success: true,
        registration_id: actualRegistrationId,
        approval_status: regObj.approval_status,
        write_confirmed: true,
        sync_confirmed: Boolean(sheetRow),
        sync_pending: !sheetRow,
        message: sheetRow
          ? 'บันทึกคำขอลงทะเบียนและส่งเข้าคิวอนุมัติเรียบร้อย'
          : 'บันทึกคำขอลงทะเบียนเรียบร้อย ระบบกำลังซิงก์รายการไปหน้าผู้ดูแล'
      });

    } catch (e) {
      return res.status(500).json({
        success: false,
        code: 'REGISTRATION_SERVER_ERROR',
        message: `ลงทะเบียนไม่สำเร็จ: ${e.message}`
      });
    }
  }

  // Step 4 Approve Registration
  if (action === 'approveRegistration') {
    try {
      const gasRes = await callCurrentGasApi('approveRegistration', data, 'POST');
      if (gasRes.success && gasRes.data) {
        if (gasRes.data.success !== false && store.registrations) {
          const item = store.registrations.find(r => r.registration_id === data.registration_id);
          if (item) {
            item.approval_status = 'APPROVED';
            item.approved_by = data.approved_by || 'Admin';
            item.approved_at = new Date().toISOString();
            saveData();
          }
        }
        return res.json(gasRes.data);
      } else {
        return res.json({ success: false, message: gasRes.error || 'ไม่สามารถอนุมัติได้' });
      }
    } catch (e) {
      return res.status(500).json({ success: false, message: e.message });
    }
  }

  // Step 4 Reject Registration
  if (action === 'rejectRegistration') {
    try {
      const gasRes = await callCurrentGasApi('rejectRegistration', data, 'POST');
      if (gasRes.success && gasRes.data) {
        if (gasRes.data.success !== false && store.registrations) {
          const item = store.registrations.find(r => r.registration_id === data.registration_id);
          if (item) {
            item.approval_status = 'REJECTED';
            item.approved_by = data.approved_by || 'Admin';
            item.remark = data.remark || '';
            item.rejected_at = new Date().toISOString();
            saveData();
          }
        }
        return res.json(gasRes.data);
      } else {
        return res.json({ success: false, message: gasRes.error || 'ไม่สามารถบันทึกการไม่อนุมัติได้' });
      }
    } catch (e) {
      return res.status(500).json({ success: false, message: e.message });
    }
  }

  // Step 4 Cancel Registration
  if (action === 'cancelRegistration') {
    try {
      const gasRes = await callCurrentGasApi('cancelRegistration', data, 'POST');
      if (gasRes.success && gasRes.data) {
        if (gasRes.data.success !== false && store.registrations) {
          const item = store.registrations.find(r => r.registration_id === data.registration_id);
          if (item) {
            item.approval_status = 'CANCELLED';
            item.cancelled_by = data.cancelled_by || 'User';
            item.cancelled_at = new Date().toISOString();
            saveData();
          }
        }
        return res.json(gasRes.data);
      } else {
        return res.json({ success: false, message: gasRes.error || 'ไม่สามารถยกเลิกได้' });
      }
    } catch (e) {
      return res.status(500).json({ success: false, message: e.message });
    }
  }

  // Step 4 / v2 Create Meeting on GAS
  if (action === 'createMeeting') {
    try {
      const gasRes = await callCurrentGasApi('createMeeting', data, 'POST');
      if (gasRes.success && gasRes.data) {
        return res.json(gasRes.data);
      } else {
        return res.json({ success: false, message: gasRes.error || 'ไม่สามารถสร้างการประชุมได้' });
      }
    } catch (e) {
      return res.status(500).json({ success: false, message: e.message });
    }
  }

  // V4.15 Update Meeting — Google Sheets / GAS is authoritative.
  if (action === 'updateMeeting') {
    try {
      const meetingId = String(data.meeting_id || data.id || '').trim();

      if (!meetingId) {
        return res.status(400).json({
          success: false,
          message: 'ไม่พบรหัสการประชุมสำหรับแก้ไข'
        });
      }

      const gasRes = await callCurrentGasApi(
        'updateMeeting',
        { ...data, meeting_id: meetingId },
        'POST'
      );

      if (!gasRes.success) {
        return res.status(502).json({
          success: false,
          message: gasRes.error || 'เชื่อมต่อ Google Apps Script เพื่อแก้ไขการประชุมไม่สำเร็จ'
        });
      }

      if (!gasRes.data || gasRes.data.success !== true) {
        return res.status(400).json({
          success: false,
          message:
            gasRes.data?.message ||
            gasRes.data?.error ||
            'Apps Script ยังไม่รองรับ updateMeeting หรือไม่สามารถแก้ไขรายการได้'
        });
      }

      return res.json(gasRes.data);
    } catch (e) {
      return res.status(502).json({
        success: false,
        message: 'แก้ไขการประชุมไม่สำเร็จ: ' + e.message
      });
    }
  }

  // Step 5 Verify Meeting Eligibility
  if (action === 'verifyMeetingEligibility') {
    try {
      const gasRes = await callCurrentGasApi('verifyMeetingEligibility', data, 'POST');
      if (gasRes.success && gasRes.data && gasRes.data.success !== false) {
        return res.json(gasRes.data);
      }
    } catch (e) {
      console.warn('Fallback verifyMeetingEligibility to local store:', e.message);
    }

    const meetingId = data.meeting_id || data.meetingId;
    const registrationId = String(data.registration_id || '').trim();
    const empCode = (data.employee_code || '').trim().toLowerCase();
    const fullname = (data.fullname || '').trim().toLowerCase();
    const fullnameEn = (data.fullname_en || '').trim().toLowerCase();

    const regs = (store.registrations || []).map(normalizeRegistrationRow);
    const match = regs.find(r => {
      if (r.meeting_id !== meetingId) return false;

      if (registrationId && r.registration_id === registrationId) return true;

      const rEmp = (r.employee_code || '').trim().toLowerCase();
      const rName = (r.fullname || '').trim().toLowerCase();
      const rNameEn = (r.fullname_en || '').trim().toLowerCase();

      if (empCode && rEmp && rEmp === empCode) return true;
      if (fullname && rName && rName === fullname) return true;
      if (fullnameEn && rNameEn && rNameEn === fullnameEn) return true;

      return false;
    });

    if (match) {
      const status = (match.approval_status || '').toUpperCase();
      if (status === 'APPROVED') {
        return res.json({
          success: true,
          eligible: true,
          message: '✅ ได้รับอนุมัติให้เข้าร่วมประชุม',
          data: {
            registration_id: match.registration_id,
            fullname: match.fullname,
            fullname_en: match.fullname_en || '',
            employee_code: match.employee_code,
            participant_type: match.participant_type,
            approval_status: 'APPROVED'
          }
        });
      } else if (status === 'PENDING') {
        return res.json({
          success: false,
          eligible: false,
          message: 'ท่านยังไม่ได้รับอนุมัติให้เข้าร่วมการประชุมนี้ (สถานะ: รอการอนุมัติ)'
        });
      } else if (status === 'REJECTED') {
        return res.json({
          success: false,
          eligible: false,
          message: 'ท่านไม่ได้รับอนุมัติให้เข้าร่วมการประชุมนี้ (สถานะ: ไม่อนุมัติ)'
        });
      } else {
        return res.json({
          success: false,
          eligible: false,
          message: `คำขอเข้าร่วมประชุมอยู่ในสถานะ ${status}`
        });
      }
    }

    // Also check if participant is explicitly in meeting participants list
    const mtg = (store.meetings || []).find(m => (m.meeting_id === meetingId || m.id === meetingId));
    if (mtg && mtg.participants) {
      const parts = Array.isArray(mtg.participants) ? mtg.participants : mtg.participants.split(',').map(s=>s.trim().toLowerCase());
      const isParticipant = parts.some(p => fullname && (p === fullname || p.includes(fullname) || fullname.includes(p)));
      if (isParticipant) {
        return res.json({
          success: true,
          eligible: true,
          message: '✅ ได้รับอนุมัติให้เข้าร่วมประชุม (รายชื่อตามวาระ)',
          data: {
            fullname: data.fullname,
            employee_code: data.employee_code || '',
            participant_type: 'INTERNAL',
            approval_status: 'APPROVED'
          }
        });
      }
    }

    return res.json({
      success: false,
      eligible: false,
      message: 'ท่านยังไม่ได้รับอนุมัติให้เข้าร่วมการประชุมนี้'
    });
  }

  // Step 5 Meeting Check-In — Google Sheets is the single source of truth.
  if (action === 'meetingCheckIn') {
    try {
      const gasRes = await callCurrentGasApi('meetingCheckIn', data, 'POST');

      if (!gasRes.success) {
        return res.status(502).json({
          success: false,
          message: gasRes.error || 'ไม่สามารถเชื่อมต่อ Google Apps Script เพื่อบันทึก Check-in ได้'
        });
      }

      const upstream = gasRes.data;
      if (!upstream || upstream.success !== true) {
        return res.status(400).json(upstream || {
          success: false,
          message: 'Google Apps Script ไม่ยืนยันการบันทึก Check-in'
        });
      }

      // Optional local mirror only AFTER Google Sheets succeeded.
      if (!store.meetingAttendance) store.meetingAttendance = [];
      const mirror = {
        ...upstream,
        meeting_id: data.meeting_id,
        employee_code: data.employee_code,
        fullname: upstream.fullname || data.fullname
      };
      const idx = store.meetingAttendance.findIndex(a =>
        a.meeting_id === data.meeting_id &&
        (a.employee_code === data.employee_code || a.fullname === data.fullname)
      );
      if (idx >= 0) store.meetingAttendance[idx] = { ...store.meetingAttendance[idx], ...mirror };
      else store.meetingAttendance.unshift(mirror);
      saveData();

      return res.json(upstream);
    } catch (e) {
      console.error('meetingCheckIn failed:', e);
      return res.status(502).json({
        success: false,
        message: 'บันทึก Check-in ไม่สำเร็จ: ' + e.message
      });
    }
  }

  // Step 5 Meeting Check-Out — Google Sheets is the single source of truth.
  if (action === 'meetingCheckOut') {
    try {
      const gasRes = await callCurrentGasApi('meetingCheckOut', data, 'POST');

      if (!gasRes.success) {
        return res.status(502).json({
          success: false,
          message: gasRes.error || 'ไม่สามารถเชื่อมต่อ Google Apps Script เพื่อบันทึก Check-out ได้'
        });
      }

      const upstream = gasRes.data;
      if (!upstream || upstream.success !== true) {
        return res.status(400).json(upstream || {
          success: false,
          message: 'Google Apps Script ไม่ยืนยันการบันทึก Check-out'
        });
      }

      // Optional local mirror only AFTER Google Sheets succeeded.
      if (!store.meetingAttendance) store.meetingAttendance = [];
      const idx = store.meetingAttendance.findIndex(a =>
        a.meeting_id === data.meeting_id &&
        (a.employee_code === data.employee_code || a.fullname === data.fullname)
      );
      if (idx >= 0) {
        store.meetingAttendance[idx] = { ...store.meetingAttendance[idx], ...upstream };
        saveData();
      }

      return res.json(upstream);
    } catch (e) {
      console.error('meetingCheckOut failed:', e);
      return res.status(502).json({
        success: false,
        message: 'บันทึก Check-out ไม่สำเร็จ: ' + e.message
      });
    }
  }

  // Step 5 Finalize Meeting Attendance
  if (action === 'finalizeMeetingAttendance') {
    try {
      const gasRes = await callCurrentGasApi('finalizeMeetingAttendance', data, 'POST');
      if (gasRes.success && gasRes.data) {
        return res.json(gasRes.data);
      }
    } catch (e) {
      console.warn('Fallback finalizeMeetingAttendance to local store:', e.message);
    }

    const meetingId = data.meeting_id || data.meetingId;
    if (!meetingId) {
      return res.json({ success: false, message: 'meeting_id is required' });
    }

    // 1. Update meeting status to COMPLETED
    const mtg = (store.meetings || []).find(m => (m.meeting_id === meetingId || m.id === meetingId));
    if (mtg) {
      mtg.status = 'COMPLETED';
    }

    // 2. Mark approved attendees without check-in as ABSENT
    const approvedRegs = (store.registrations || []).filter(r => r.meeting_id === meetingId && (r.approval_status || '').toUpperCase() === 'APPROVED');
    if (!store.meetingAttendance) store.meetingAttendance = [];

    approvedRegs.forEach(reg => {
      const exists = store.meetingAttendance.find(a => (a.meeting_id === meetingId || a.meetingId === meetingId) && (a.fullname === reg.fullname || a.participantName === reg.fullname));
      if (!exists) {
        store.meetingAttendance.push({
          attendance_id: 'ATT-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
          meeting_id: meetingId,
          employee_code: reg.employee_code || '',
          fullname: reg.fullname,
          participant_type: reg.participant_type || 'INTERNAL',
          check_in_time: '-',
          check_out_time: '-',
          check_in_status: 'ABSENT',
          final_status: 'ABSENT',
          face_verified: false,
          created_at: new Date().toISOString()
        });
      }
    });

    // 3. Mark check-ins without check-out as INCOMPLETE
    store.meetingAttendance.forEach(a => {
      if ((a.meeting_id === meetingId || a.meetingId === meetingId)) {
        if (a.check_in_time && a.check_in_time !== '-' && (!a.check_out_time || a.check_out_time === '')) {
          a.final_status = 'INCOMPLETE';
        }
      }
    });

    saveData();

    return res.json({
      success: true,
      message: 'สรุปผลการเข้าร่วมประชุมเรียบร้อยแล้ว',
      meeting_id: meetingId,
      status: 'COMPLETED'
    });
  }

  // Register User Face & Persist to Google Apps Script
  if (action === 'registerUser') {
    const { name, fullname, employee_code, employeeCode, faceDescriptor, descriptor, department, position, email, photo } = data;
    const finalCode = (employee_code || employeeCode || '').trim();
    const finalName = (fullname || name || '').trim();
    const rawDesc = descriptor || faceDescriptor;

    if (!finalCode) {
      return res.status(400).json({ success: false, message: 'กรุณาระบุรหัสบุคลากร (employee_code)' });
    }
    if (!finalName) {
      return res.status(400).json({ success: false, message: 'กรุณาระบุชื่อ-นามสกุล (fullname)' });
    }
    if (!rawDesc) {
      return res.status(400).json({ success: false, message: 'ไม่สามารถสร้างข้อมูลใบหน้าได้ กรุณามองตรงที่กล้องแล้วลองใหม่' });
    }

    // Convert Float32Array or array-like object to regular JS Array of numbers
    let descriptorArray = null;
    if (Array.isArray(rawDesc)) {
      descriptorArray = rawDesc.map(v => typeof v === 'number' ? v : parseFloat(v));
    } else if (rawDesc instanceof Float32Array || (typeof rawDesc === 'object' && rawDesc !== null)) {
      descriptorArray = Array.from(rawDesc).map(v => typeof v === 'number' ? v : parseFloat(v));
    }

    if (!descriptorArray || !Array.isArray(descriptorArray) || descriptorArray.length !== 128 || descriptorArray.some(isNaN)) {
      return res.status(400).json({
        success: false,
        message: 'ข้อมูลใบหน้าไม่สมบูรณ์ กรุณาสแกนใหม่ (ต้องมี 128 มิติ)',
        descriptorLength: descriptorArray ? descriptorArray.length : 0
      });
    }

    // Prepare gas payload with both v2 and v3 format aliases
    const gasPayload = {
      action: 'registerUser',
      employee_code: finalCode,
      fullname: finalName,
      name: finalName,
      label: `${finalCode} - ${finalName}`,
      descriptor: descriptorArray,
      faceDescriptor: descriptorArray,
      department: department || '',
      position: position || '',
      email: email || '',
      photo: photo || ''
    };

    console.log('[RegisterUser] Employee code:', finalCode);
    console.log('[RegisterUser] Full name:', finalName);
    console.log('[RegisterUser] Descriptor length:', descriptorArray.length);

    let gasRes = null;
    let gasSuccess = false;
    try {
      gasRes = await callCurrentGasApi('registerUser', gasPayload, 'POST');
      console.log('[RegisterUser] GAS response:', gasRes);
      if (gasRes && gasRes.success && gasRes.data && gasRes.data.success === true) {
        gasSuccess = true;
      }
    } catch (e) {
      console.warn('[RegisterUser] GAS call failed:', e.message);
    }

    // Google Sheets is the source of truth. Never report success when GAS persistence failed.
    if (!gasSuccess) {
      const gasErrMsg = gasRes?.data?.message || gasRes?.data?.error || gasRes?.error || 'Google Apps Script ไม่ยืนยันการบันทึก';
      return res.status(502).json({
        success: false,
        message: 'บันทึกใบหน้าไม่สำเร็จ: ' + gasErrMsg,
        gasSynced: false
      });
    }

    // Update local cache only AFTER Google Apps Script confirms persistence.
    if (!store.knownFaces) store.knownFaces = [];
    const existingIndex = store.knownFaces.findIndex(f =>
      (finalCode && (f.employee_code === finalCode || f.id === finalCode || f.id === 'emp_' + finalCode)) ||
      (finalName && (f.fullname === finalName || f.name === finalName || f.label === finalName))
    );

    const oldEmp = existingIndex >= 0 ? store.knownFaces[existingIndex] : {};
    const newFace = {
      id: oldEmp.id || (finalCode ? 'emp_' + finalCode : 'emp_' + Date.now()),
      employee_code: finalCode,
      label: `${finalCode} - ${finalName}`,
      fullname: finalName,
      name: finalName,
      descriptor: descriptorArray,
      faceDescriptor: descriptorArray,
      department: department || oldEmp.department || 'ทั่วไป',
      position: position || oldEmp.position || 'พนักงาน',
      email: email || oldEmp.email || '',
      photo: photo || oldEmp.photo || '',
      createdAt: oldEmp.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    if (existingIndex >= 0) {
      store.knownFaces[existingIndex] = { ...oldEmp, ...newFace };
    } else {
      store.knownFaces.push(newFace);
    }
    saveData();

    return res.json({
      success: true,
      message: gasRes.data?.message || 'ข้อมูลใบหน้าได้รับการบันทึกใน Google Sheets แล้ว',
      employee_code: finalCode,
      fullname: finalName,
      data: newFace,
      gasSynced: true
    });
  }

  if (action === 'logAttendance') {
    const { name, lat, lng, photo } = data;
    const now = new Date();
    const mapLink = lat && lng ? `https://www.google.com/maps?q=${lat},${lng}` : '';
    const dateStr = now.toLocaleDateString('th-TH');
    const timeStr = now.toLocaleTimeString('th-TH');

    let distance = 0;
    let isWithinRadius = true;
    if (store.gpsConfig.radius > 0 && store.gpsConfig.lat && store.gpsConfig.lng && lat && lng) {
      distance = getDistanceMeters(store.gpsConfig.lat, store.gpsConfig.lng, parseFloat(lat), parseFloat(lng));
      isWithinRadius = distance <= store.gpsConfig.radius;
    }

    // Determine on-time vs late (Standard cutoff 09:00 AM)
    const hours = now.getHours();
    const minutes = now.getMinutes();
    const isLate = hours > 9 || (hours === 9 && minutes > 0);

    const logEntry = {
      id: 'att_' + Date.now(),
      name,
      time: timeStr,
      date: dateStr,
      lat: lat || '-',
      lng: lng || '-',
      mapLink,
      distance,
      isWithinRadius,
      status: isLate ? 'late' : 'on_time',
      type: 'work_checkin',
      photo: photo || '',
      timestamp: now.toISOString()
    };

    store.attendanceLogs.unshift(logEntry);
    saveData();
    return res.json({
      success: true,
      message: `บันทึกเวลาสำเร็จ (${isLate ? 'เข้างานสาย' : 'ตรงเวลา'})`,
      log: logEntry
    });
  }

  // v1 Save GPS & Office Config
  if (action === 'saveConfig') {
    const { lat, lng, radius, officeName, gas_url, gasUrl } = data;
    const requestedGasUrl = String(gas_url || gasUrl || store.gasWebAppUrl || GAS_WEBAPP_URL || '').trim();

    if (!/^https:\/\/script\.google\.com\/macros\/s\/[^/]+\/exec(?:$|\?)/.test(requestedGasUrl)) {
      return res.status(400).json({
        success: false,
        message: 'Google Apps Script URL ไม่ถูกต้อง กรุณาใช้ Web App URL ที่ลงท้ายด้วย /exec'
      });
    }

    store.gasWebAppUrl = requestedGasUrl;
    store.gpsConfig = {
      lat: parseFloat(lat) || 0,
      lng: parseFloat(lng) || 0,
      radius: parseFloat(radius) || 0,
      officeName: officeName || store.gpsConfig.officeName || 'สำนักงานใหญ่'
    };
    saveData();

    // Verify the newly saved URL immediately.
    const ping = await callGasApi('ping', {}, 'GET', 15000, requestedGasUrl);
    if (!ping.success || !ping.data || ping.data.success === false) {
      return res.status(502).json({
        success: false,
        message: ping.data?.message || ping.error || 'บันทึก URL แล้ว แต่ไม่สามารถเชื่อมต่อ Apps Script ได้'
      });
    }

    return res.json({
      success: true,
      message: 'บันทึกการตั้งค่าและเชื่อมต่อ Google Apps Script สำเร็จ',
      config: store.gpsConfig,
      gasVersion: ping.data.version || null
    });
  }

  // v2 Create or Update Meeting
  if (action === 'saveMeeting') {
    const meetingData = data.meeting;
    if (!meetingData || !meetingData.title) {
      return res.status(400).json({ error: 'Meeting title is required' });
    }

    if (meetingData.id) {
      const idx = store.meetings.findIndex(m => m.id === meetingData.id);
      if (idx >= 0) {
        store.meetings[idx] = { ...store.meetings[idx], ...meetingData, updatedAt: new Date().toISOString() };
      } else {
        store.meetings.push({ ...meetingData, createdAt: new Date().toISOString() });
      }
    } else {
      const newMeeting = {
        ...meetingData,
        id: 'mtg_' + Date.now(),
        status: meetingData.status || 'scheduled',
        participants: meetingData.participants || [],
        createdAt: new Date().toISOString()
      };
      store.meetings.unshift(newMeeting);
    }
    saveData();
    return res.json({ success: true, message: 'บันทึกข้อมูลการประชุมเรียบร้อย', meetings: store.meetings });
  }

  // V4.15 Delete Meeting — Google Sheets is authoritative.
  if (action === 'deleteMeeting') {
    const meetingId = String(data.meeting_id || data.id || '').trim();

    if (!meetingId) {
      return res.status(400).json({
        success: false,
        message: 'ไม่พบรหัสการประชุมที่ต้องการลบ'
      });
    }

    try {
      const gasRes = await callCurrentGasApi(
        'deleteMeeting',
        { meeting_id: meetingId, id: meetingId },
        'POST'
      );

      if (!gasRes.success) {
        return res.status(502).json({
          success: false,
          message: gasRes.error || 'เชื่อมต่อ Google Apps Script เพื่อลบการประชุมไม่สำเร็จ'
        });
      }

      if (!gasRes.data || gasRes.data.success !== true) {
        return res.status(400).json({
          success: false,
          message:
            gasRes.data?.message ||
            gasRes.data?.error ||
            'Apps Script ยังไม่รองรับ deleteMeeting หรือไม่สามารถลบรายการได้'
        });
      }

      store.meetings = (store.meetings || []).filter(
        m => (m.meeting_id || m.id) !== meetingId
      );
      store.meetingAttendance = (store.meetingAttendance || []).filter(
        a => (a.meeting_id || a.meetingId) !== meetingId
      );
      store.registrations = (store.registrations || []).filter(
        r => r.meeting_id !== meetingId
      );
      saveData();

      return res.json(gasRes.data);
    } catch (e) {
      return res.status(502).json({
        success: false,
        message: 'ลบการประชุมไม่สำเร็จ: ' + e.message
      });
    }
  }

  // v3 Log Meeting Attendance (Face Recognition + GPS)
  if (action === 'logMeetingAttendance') {
    const { meetingId, participantName, lat, lng, confidence, photo } = data;
    if (!meetingId || !participantName) {
      return res.status(400).json({ error: 'Meeting ID and Participant Name are required' });
    }

    const meeting = store.meetings.find(m => m.id === meetingId);
    const now = new Date();
    const timeStr = now.toLocaleTimeString('th-TH');
    const dateStr = now.toLocaleDateString('th-TH');

    let status = 'on_time';
    if (meeting && meeting.date && meeting.startTime) {
      const [sh, sm] = meeting.startTime.split(':').map(Number);
      const meetingStart = new Date(`${meeting.date}T${String(sh).padStart(2, '0')}:${String(sm).padStart(2, '0')}:00`);
      if (now > meetingStart) {
        status = 'late';
      }
    }

    let distance = 0;
    if (meeting && meeting.gpsRequired && meeting.gpsLat && meeting.gpsLng && lat && lng) {
      distance = getDistanceMeters(meeting.gpsLat, meeting.gpsLng, parseFloat(lat), parseFloat(lng));
    }

    // Check if already checked in
    const existingIdx = store.meetingAttendance.findIndex(
      a => a.meetingId === meetingId && a.participantName === participantName
    );

    const record = {
      id: existingIdx >= 0 ? store.meetingAttendance[existingIdx].id : 'matt_' + Date.now(),
      meetingId,
      participantName,
      checkInTime: timeStr,
      checkInDate: dateStr,
      status,
      lat: lat || '-',
      lng: lng || '-',
      distance,
      confidence: confidence || 0.95,
      photo: photo || '',
      timestamp: now.toISOString()
    };

    if (existingIdx >= 0) {
      store.meetingAttendance[existingIdx] = record;
    } else {
      store.meetingAttendance.unshift(record);
    }
    saveData();

    return res.json({
      success: true,
      message: `เช็คชื่อเข้าประชุมสำเร็จ (${status === 'late' ? 'เข้าร่วมสาย' : 'ตรงเวลา'})`,
      record
    });
  }

  // v5/v6 Save Transcript & AI Summary to Meeting
  if (action === 'saveMeetingMinutes') {
    const { meetingId, transcript, aiSummary } = data;
    const meeting = store.meetings.find(m => m.id === meetingId);
    if (!meeting) {
      return res.status(404).json({ error: 'Meeting not found' });
    }
    if (transcript !== undefined) meeting.transcript = transcript;
    if (aiSummary !== undefined) meeting.aiSummary = aiSummary;
    meeting.status = 'completed';
    meeting.updatedAt = new Date().toISOString();
    saveData();
    return res.json({ success: true, message: 'บันทึกบันทึกการประชุมและสรุป AI เรียบร้อย', meeting });
  }

  // Delete User Face
  if (action === 'deleteUserFace') {
    const { id, label } = data;
    store.knownFaces = store.knownFaces.filter(f => (id ? f.id !== id : f.label !== label));
    saveData();
    return res.json({ success: true, message: 'ลบข้อมูลใบหน้าเรียบร้อย' });
  }

  return res.status(400).json({ error: 'Unknown action: ' + action });
});

// -------------------------------------------------------------
// Public AI rate guard for menu 5
// Everyone may use the feature, but excessive automated requests are limited.
// -------------------------------------------------------------
const PUBLIC_AI_RATE_LIMIT = {
  windowMs: 10 * 60 * 1000,
  maxRequests: 20
};
const publicAiUsage = new Map();

function publicAiClientKey(req) {
  return String(
    req.headers['x-forwarded-for'] ||
    req.socket?.remoteAddress ||
    'unknown'
  ).split(',')[0].trim();
}

function allowPublicAiRequest(req, res) {
  const key = publicAiClientKey(req);
  const now = Date.now();
  let state = publicAiUsage.get(key);

  if (!state || now - state.startedAt >= PUBLIC_AI_RATE_LIMIT.windowMs) {
    state = { startedAt: now, count: 0 };
  }

  state.count += 1;
  publicAiUsage.set(key, state);

  if (state.count > PUBLIC_AI_RATE_LIMIT.maxRequests) {
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((PUBLIC_AI_RATE_LIMIT.windowMs - (now - state.startedAt)) / 1000)
    );
    res.setHeader('Retry-After', String(retryAfterSeconds));
    res.status(429).json({
      success: false,
      code: 'AI_RATE_LIMIT',
      message: 'มีการใช้งาน AI จากอุปกรณ์นี้ถี่เกินไป กรุณารอสักครู่แล้วลองใหม่'
    });
    return false;
  }

  return true;
}

// -------------------------------------------------------------
// v9.2 Smart Meeting AI — REAL Gemini + resilient summary retry/fallback
// Stable attendance core is unchanged.
// -------------------------------------------------------------

const GEMINI_SUMMARY_MODEL = process.env.GEMINI_SUMMARY_MODEL || 'gemini-3.7-flash';
const GEMINI_SUMMARY_FALLBACK_MODELS = String(
  process.env.GEMINI_SUMMARY_FALLBACK_MODELS || 'gemini-3.6-flash,gemini-3.5-flash'
)
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);
const GEMINI_TRANSCRIBE_MODEL = process.env.GEMINI_TRANSCRIBE_MODEL || 'gemini-3.5-transcribe';

function getGeminiApiKey() {
  return String(
    process.env.GEMINI_API_KEY ||
    process.env.GOOGLE_API_KEY ||
    ''
  ).trim();
}

function getGeminiClient() {
  const apiKey = getGeminiApiKey();
  return apiKey ? new GoogleGenAI({ apiKey }) : null;
}

function audioExtensionFromMime(mimeType = '') {
  const type = String(mimeType).split(';')[0].trim().toLowerCase();
  const map = {
    'audio/wav': 'wav',
    'audio/x-wav': 'wav',
    'audio/mp3': 'mp3',
    'audio/mpeg': 'mp3',
    'audio/aiff': 'aiff',
    'audio/aac': 'aac',
    'audio/ogg': 'ogg',
    'audio/flac': 'flac'
  };
  return map[type] || 'wav';
}

function normalizeAudioMime(mimeType = '') {
  const type = String(mimeType).split(';')[0].trim().toLowerCase();
  if (type === 'audio/mpeg') return 'audio/mp3';
  if (type === 'audio/x-wav') return 'audio/wav';
  return type || 'audio/wav';
}

app.get('/api/ai/status', (req, res) => {
  const configured = Boolean(getGeminiApiKey());

  return res.json({
    success: true,
    configured,
    model: GEMINI_SUMMARY_MODEL,
    summaryModel: GEMINI_SUMMARY_MODEL,
    summaryFallbackModels: GEMINI_SUMMARY_FALLBACK_MODELS,
    transcribeModel: GEMINI_TRANSCRIBE_MODEL,
    message: configured
      ? 'Gemini AI พร้อมใช้งาน'
      : 'ยังไม่ได้ตั้งค่า GEMINI_API_KEY'
  });
});

app.post('/api/ai/transcribe-audio', async (req, res) => {
  if (!allowPublicAiRequest(req, res)) return;

  let tempPath = '';

  try {
    const { audioData, mimeType, meetingContext } = req.body || {};

    if (!audioData) {
      return res.status(400).json({
        success: false,
        message: 'ไม่พบไฟล์เสียงสำหรับถอดข้อความ'
      });
    }

    const ai = getGeminiClient();
    if (!ai) {
      return res.status(503).json({
        success: false,
        code: 'GEMINI_API_KEY_MISSING',
        message: 'ยังไม่ได้ตั้งค่า Gemini API Key ใน Server'
      });
    }

    const normalizedMime = normalizeAudioMime(mimeType);
    const supportedMime = new Set([
      'audio/wav',
      'audio/mp3',
      'audio/aiff',
      'audio/aac',
      'audio/ogg',
      'audio/flac'
    ]);

    if (!supportedMime.has(normalizedMime)) {
      return res.status(415).json({
        success: false,
        code: 'UNSUPPORTED_AUDIO_FORMAT',
        message: `รูปแบบเสียง ${normalizedMime} ยังไม่รองรับ กรุณาใช้ WAV, MP3, AIFF, AAC, OGG หรือ FLAC`
      });
    }

    const cleanBase64 = String(audioData)
      .replace(/^data:[^;]+;base64,/, '')
      .replace(/\s/g, '');

    let audioBuffer;
    try {
      audioBuffer = Buffer.from(cleanBase64, 'base64');
    } catch {
      return res.status(400).json({
        success: false,
        message: 'ข้อมูลไฟล์เสียง Base64 ไม่ถูกต้อง'
      });
    }

    if (!audioBuffer.length) {
      return res.status(400).json({
        success: false,
        message: 'ไฟล์เสียงมีขนาด 0 byte'
      });
    }

    const maxBytes = 20 * 1024 * 1024;
    if (audioBuffer.length > maxBytes) {
      return res.status(413).json({
        success: false,
        code: 'AUDIO_TOO_LARGE',
        message: 'ไฟล์เสียงเกิน 20 MB สำหรับขั้นทดสอบนี้ กรุณาบันทึกช่วงสั้นลง'
      });
    }

    const ext = audioExtensionFromMime(normalizedMime);
    tempPath = path.join(
      __dirname,
      `.meeting-audio-${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`
    );

    fs.writeFileSync(tempPath, audioBuffer);

    const uploadedFile = await ai.files.upload({
      file: tempPath,
      config: {
        mimeType: normalizedMime
      }
    });

    // Gemini 3.5 Transcribe (current API) expects an audio URI input.
    // Do NOT pass the raw uploadedFile object directly into generateContent:
    // that produces "parts[0].data ... required oneof field" errors.
    const uploadedUri = uploadedFile.uri;
    const uploadedMime = uploadedFile.mimeType || uploadedFile.mime_type || normalizedMime;

    if (!uploadedUri) {
      throw new Error('Gemini Files API อัปโหลดสำเร็จแต่ไม่พบ file URI');
    }

    let transcript = '';
    let transcriptionPath = '';
    let interactionsError = null;

    // Preferred path: current Interactions API.
    // Supports speaker diarization for Gemini 3.5 Transcribe.
    if (ai.interactions && typeof ai.interactions.create === 'function') {
      try {
        const interaction = await ai.interactions.create({
          model: GEMINI_TRANSCRIBE_MODEL,
          input: [
            {
              type: 'audio',
              uri: uploadedUri,
              mime_type: uploadedMime
            }
          ],
          generation_config: {
            transcription_config: {
              language_codes: [],
              mode: {
                type: 'verbatim',
                diarization_mode: 'speaker'
              }
            }
          }
        });

        transcript = String(
          interaction.output_text ||
          interaction.outputText ||
          ''
        ).trim();

        transcriptionPath = 'interactions';
      } catch (err) {
        interactionsError = err;
        console.warn('[Gemini Interactions Transcribe fallback]', err?.message || err);
      }
    }

    // Compatibility fallback: GenerateContent with an explicit fileData part.
    // This is also valid for Gemini audio input and fixes the invalid "data" part.
    if (!transcript) {
      try {
        const response = await ai.models.generateContent({
          model: GEMINI_TRANSCRIBE_MODEL,
          contents: [
            {
              role: 'user',
              parts: [
                {
                  fileData: {
                    fileUri: uploadedUri,
                    mimeType: uploadedMime
                  }
                }
              ]
            }
          ]
        });

        transcript = String(response.text || '').trim();
        transcriptionPath = 'generateContent-fileData';
      } catch (fallbackErr) {
        const firstError = interactionsError
          ? `Interactions API: ${interactionsError.message || interactionsError}; `
          : '';

        throw new Error(
          `${firstError}GenerateContent fallback: ${fallbackErr.message || fallbackErr}`
        );
      }
    }

    if (!transcript) {
      return res.status(502).json({
        success: false,
        message: 'Gemini ไม่ได้ส่งข้อความถอดเสียงกลับมา'
      });
    }

    return res.json({
      success: true,
      model: GEMINI_TRANSCRIBE_MODEL,
      transcriptionPath,
      transcript,
      context: meetingContext || ''
    });

  } catch (err) {
    console.error('[AI Transcribe Error]', err);

    return res.status(500).json({
      success: false,
      message: `ถอดเสียงไม่สำเร็จ: ${err.message || err}`
    });

  } finally {
    if (tempPath) {
      try {
        if (fs.existsSync(tempPath)) {
          fs.unlinkSync(tempPath);
        }
      } catch (cleanupErr) {
        console.warn('[AI Temp Cleanup]', cleanupErr.message);
      }
    }
  }
});


function sleepMs(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function geminiErrorText(err) {
  try {
    if (typeof err === 'string') return err;
    if (err?.message) return String(err.message);
    return JSON.stringify(err);
  } catch {
    return String(err || '');
  }
}

function isRetryableGeminiError(err) {
  const text = geminiErrorText(err).toUpperCase();

  return (
    text.includes('503') ||
    text.includes('UNAVAILABLE') ||
    text.includes('HIGH DEMAND') ||
    text.includes('429') ||
    text.includes('RESOURCE_EXHAUSTED') ||
    text.includes('500') ||
    text.includes('502') ||
    text.includes('504') ||
    text.includes('DEADLINE_EXCEEDED')
  );
}

function uniqueSummaryModels() {
  const seen = new Set();
  return [GEMINI_SUMMARY_MODEL, ...GEMINI_SUMMARY_FALLBACK_MODELS]
    .filter(Boolean)
    .filter(model => {
      if (seen.has(model)) return false;
      seen.add(model);
      return true;
    });
}

async function generateSummaryWithRetry(ai, contents) {
  const models = uniqueSummaryModels();
  const errors = [];

  for (const model of models) {
    // Two tries per model: immediate, then a short backoff.
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        if (attempt > 1) {
          await sleepMs(1500 * attempt);
        }

        const response = await ai.models.generateContent({
          model,
          contents
        });

        const text = String(response?.text || '').trim();

        if (!text) {
          throw new Error(`${model} ไม่ได้ส่งข้อความสรุปกลับมา`);
        }

        return {
          response,
          model,
          attempt,
          text
        };
      } catch (err) {
        const retryable = isRetryableGeminiError(err);
        const message = geminiErrorText(err);

        console.warn(
          `[AI Summary] model=${model} attempt=${attempt} retryable=${retryable}:`,
          message
        );

        errors.push({
          model,
          attempt,
          retryable,
          message
        });

        // Do not retry/fallback for bad requests/auth/schema errors.
        if (!retryable) {
          const nonRetryable = new Error(message);
          nonRetryable.code = 'GEMINI_NON_RETRYABLE';
          nonRetryable.details = errors;
          throw nonRetryable;
        }
      }
    }
  }

  const finalError = new Error(
    'Gemini Summary ทุกโมเดลยังไม่พร้อมใช้งานชั่วคราว กรุณาลองใหม่อีกครั้ง'
  );
  finalError.code = 'GEMINI_TEMPORARILY_UNAVAILABLE';
  finalError.details = errors;
  throw finalError;
}

app.post('/api/ai/summarize-meeting', async (req, res) => {
  if (!allowPublicAiRequest(req, res)) return;

  try {
    const {
      meetingTitle,
      agenda,
      transcript,
      attendees,
      tone,
      language
    } = req.body || {};

    if (!transcript || !String(transcript).trim()) {
      return res.status(400).json({
        success: false,
        message: 'ยังไม่มี Transcript สำหรับสรุปการประชุม'
      });
    }

    const ai = getGeminiClient();
    if (!ai) {
      return res.status(503).json({
        success: false,
        code: 'GEMINI_API_KEY_MISSING',
        message: 'ยังไม่ได้ตั้งค่า Gemini API Key ใน Server'
      });
    }

    const langPrompt = language === 'en'
      ? 'English'
      : 'ภาษาไทยแบบเป็นทางการ อ่านง่าย เหมาะสำหรับรายงานการประชุม';

    const attendeeText = Array.isArray(attendees)
      ? attendees.filter(Boolean).join(', ')
      : String(attendees || 'ไม่ระบุ');

    const instruction = `คุณคือเลขานุการการประชุมมืออาชีพ
วิเคราะห์ Transcript โดยยึดเฉพาะข้อมูลที่ปรากฏจริงเท่านั้น
ห้ามสร้างชื่อบุคคล มติ งาน กำหนดส่ง หรือข้อเท็จจริงที่ไม่ได้อยู่ใน Transcript
ถ้าไม่มีข้อมูล ให้ใช้ "ไม่ระบุ" หรือเว้นรายการนั้น
ตอบเป็น JSON เท่านั้น ห้ามใช้ Markdown
ภาษา: ${langPrompt}
รูปแบบ: ${tone || 'Professional Meeting Minutes'}

JSON schema:
{
  "executiveSummary": "สรุปภาพรวมการประชุม 1-3 ย่อหน้า",
  "keyPoints": ["ประเด็นสำคัญ"],
  "decisions": ["มติหรือข้อสรุปที่กล่าวไว้จริง"],
  "actionItems": [
    {
      "task": "งานที่ได้รับมอบหมาย",
      "assignee": "ผู้รับผิดชอบ หรือ ไม่ระบุ",
      "deadline": "กำหนดเวลา หรือ ไม่ระบุ",
      "priority": "High | Medium | Low | ไม่ระบุ",
      "status": "Pending"
    }
  ],
  "sentiment": "ภาพรวมบรรยากาศจากเนื้อหาที่มี หรือ ไม่ระบุ",
  "nextMeeting": "กำหนดประชุมครั้งถัดไป/ประเด็นติดตาม หรือ ไม่ระบุ"
}`;

    const prompt = `หัวข้อการประชุม: ${meetingTitle || 'ไม่ระบุ'}
วาระการประชุม: ${agenda || 'ไม่ระบุ'}
ผู้เข้าร่วมที่ทราบ: ${attendeeText}

Transcript:
${String(transcript).trim()}`;

    const summaryResult = await generateSummaryWithRetry(ai, [{
      role: 'user',
      parts: [{
        text: `${instruction}\n\n${prompt}`
      }]
    }]);

    const responseText = summaryResult.text;

    let summary;

    try {
      const cleanJson = responseText
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '')
        .trim();

      summary = JSON.parse(cleanJson);

    } catch (parseErr) {
      return res.status(502).json({
        success: false,
        code: 'AI_JSON_PARSE_FAILED',
        message: 'Gemini ส่งผลกลับมาแต่รูปแบบ JSON ไม่สมบูรณ์ กรุณากดสรุปใหม่',
        raw: responseText
      });
    }

    return res.json({
      success: true,
      model: summaryResult.model,
      attempt: summaryResult.attempt,
      fallbackUsed: summaryResult.model !== GEMINI_SUMMARY_MODEL,
      summary
    });

  } catch (err) {
    console.error('[AI Summary Error]', err);

    const temporary = err?.code === 'GEMINI_TEMPORARILY_UNAVAILABLE' ||
      isRetryableGeminiError(err);

    return res.status(temporary ? 503 : 500).json({
      success: false,
      code: err?.code || (temporary ? 'GEMINI_TEMPORARILY_UNAVAILABLE' : 'AI_SUMMARY_FAILED'),
      message: temporary
        ? 'Gemini มีผู้ใช้งานหนาแน่นชั่วคราว ระบบลองซ้ำและสลับโมเดลสำรองแล้ว กรุณากดสรุปอีกครั้งในภายหลัง'
        : `สรุปการประชุมไม่สำเร็จ: ${err.message || err}`,
      details: err?.details || undefined
    });
  }
});

// -------------------------------------------------------------
// v7 Dashboard Helper
// -------------------------------------------------------------
function getDashboardStats() {
  const totalEmployees = store.knownFaces.length;
  const totalWorkLogs = store.attendanceLogs.length;
  const totalMeetings = store.meetings.length;
  const totalMeetingAttendance = store.meetingAttendance.length;

  const onTimeWork = store.attendanceLogs.filter(l => l.status === 'on_time').length;
  const lateWork = store.attendanceLogs.filter(l => l.status === 'late').length;
  const workOnTimeRate = totalWorkLogs > 0 ? Math.round((onTimeWork / totalWorkLogs) * 100) : 100;

  const onTimeMeeting = store.meetingAttendance.filter(m => m.status === 'on_time').length;
  const lateMeeting = store.meetingAttendance.filter(m => m.status === 'late').length;
  const meetingOnTimeRate = totalMeetingAttendance > 0 ? Math.round((onTimeMeeting / totalMeetingAttendance) * 100) : 100;

  // Department counts
  const departmentStats = {};
  store.knownFaces.forEach(f => {
    const dept = f.department || 'ทั่วไป';
    departmentStats[dept] = (departmentStats[dept] || 0) + 1;
  });

  return {
    totalEmployees,
    totalWorkLogs,
    totalMeetings,
    totalMeetingAttendance,
    workOnTimeRate,
    onTimeWork,
    lateWork,
    meetingOnTimeRate,
    onTimeMeeting,
    lateMeeting,
    departmentStats,
    recentMeetings: store.meetings.slice(0, 5),
    recentLogs: store.attendanceLogs.slice(0, 10),
    recentMeetingAttendance: store.meetingAttendance.slice(0, 10),
    gpsConfig: store.gpsConfig
  };
}

// Serve static assets from root directory

// -------------------------------------------------------------
// Production Readiness / System Health — Admin only
// -------------------------------------------------------------
app.get('/api/production/health', async (req, res) => {
  if (!requireAdminApi(req, res)) return;

  const checks = [];

  const add = (id, label, status, message, detail = {}) => {
    checks.push({ id, label, status, message, ...detail });
  };

  const usingDefaultAdmin =
    ADMIN_USERNAME === 'admin' &&
    ADMIN_PASSWORD === '1234';

  add(
    'admin',
    'Admin Security',
    usingDefaultAdmin ? 'warning' : 'ok',
    usingDefaultAdmin
      ? 'ยังใช้ admin / 1234 — เหมาะกับการทดสอบ แต่ควรเปลี่ยนก่อนใช้งานจริง'
      : 'ใช้ Admin Secrets แล้ว',
    { previewTokenAllowed: ALLOW_PREVIEW_ADMIN_TOKEN }
  );

  add(
    'gemini',
    'Gemini AI',
    getGeminiApiKey() ? 'ok' : 'error',
    getGeminiApiKey()
      ? 'Gemini API Key พร้อมใช้งาน'
      : 'ยังไม่ได้ตั้ง GEMINI_API_KEY'
  );

  add(
    'records-config',
    'Meeting Records Security',
    recordsProxyConfigured() ? 'ok' : 'error',
    recordsProxyConfigured()
      ? 'Records API URL และ Shared Token ถูกเก็บฝั่ง Server'
      : 'ยังไม่ได้ตั้ง MEETING_RECORDS_API_URL / MEETING_RECORDS_API_TOKEN'
  );

  try {
    const gas = await callCurrentGasApi('ping');

    add(
      'gas',
      'Smart Meeting Apps Script',
      gas?.success && gas?.data?.success === true ? 'ok' : 'error',
      gas?.success && gas?.data?.success === true
        ? 'เชื่อมต่อ API หลักสำเร็จ'
        : 'API หลักตอบกลับผิดปกติ'
    );
  } catch (err) {
    add('gas', 'Smart Meeting Apps Script', 'error', err.message || String(err));
  }

  try {
    if (!recordsProxyConfigured()) {
      throw new Error('Records Proxy ยังไม่ได้ตั้งค่า');
    }

    const recordCheck = await callRecordsApi('systemCheck');

    add(
      'records',
      'Google Sheets / Drive Records',
      'ok',
      `MeetingRecords และ Drive พร้อมใช้งาน (${recordCheck.sheet_rows || 0} records)`,
      { version: recordCheck.version || null }
    );
  } catch (err) {
    add('records', 'Google Sheets / Drive Records', 'error', err.message || String(err));
  }

  try {
    const faces = await callCurrentGasApi('getKnownFaces');
    const payload = faces?.data || {};
    const list = Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload?.faces)
        ? payload.faces
        : Array.isArray(payload?.knownFaces)
          ? payload.knownFaces
          : [];

    add(
      'faces',
      'Face Database',
      'ok',
      `เชื่อมต่อฐานใบหน้าได้ (${list.length} ใบหน้า)`
    );
  } catch (err) {
    add('faces', 'Face Database', 'warning', err.message || String(err));
  }

  const hasError = checks.some(c => c.status === 'error');
  const hasWarning = checks.some(c => c.status === 'warning');

  return res.json({
    success: !hasError,
    overall: hasError ? 'error' : hasWarning ? 'warning' : 'ok',
    version: 'PRODUCTION-V1.0',
    checks,
    recommendations: [
      usingDefaultAdmin
        ? 'เปลี่ยน ADMIN_PASSWORD จาก 1234 ก่อน Publish จริง'
        : null,
      ALLOW_PREVIEW_ADMIN_TOKEN
        ? 'ก่อน Publish จริง ให้ตั้ง ALLOW_PREVIEW_ADMIN_TOKEN=false'
        : null,
      !recordsProxyConfigured()
        ? 'ตั้ง MEETING_RECORDS_API_URL และ MEETING_RECORDS_API_TOKEN ใน Secrets'
        : null
    ].filter(Boolean),
    timestamp: new Date().toISOString()
  });
});

app.use(express.static(__dirname));

// Fallback for HTML5 navigation
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Face Recognition, GPS, Smart Meeting AI & Admin Auth server running on http://0.0.0.0:${PORT}`);
});
