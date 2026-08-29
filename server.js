const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'beulah-data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const now = () => new Date().toISOString();
const id = prefix => `${prefix}-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
const clean = (value, max = 5000) => String(value ?? '').trim().slice(0, max);

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(String(password), salt, 64).toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(String(password), salt, 64).toString('hex');
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function initialDb() {
  return {
    users: [
      { id: 'USR-ADMIN-001', role: 'admin', firstName: 'Clinic', lastName: 'Administrator', email: 'admin@beulah.test', passwordHash: hashPassword('Admin123!'), adminId: 'ADMIN-001' },
      { id: 'USR-STAFF-001', role: 'staff', firstName: 'Clinic', lastName: 'Staff', email: 'staff@beulah.test', passwordHash: hashPassword('Staff123!'), staffId: 'STAFF-001' },
      { id: 'USR-DOCTOR-001', role: 'doctor', firstName: 'Clinic', lastName: 'Doctor', email: 'doctor@beulah.test', passwordHash: hashPassword('Doctor123!'), doctorId: 'DOC-001' }
    ],
    appointments: [],
    vitals: [],
    prescriptions: [],
    payments: [],
    consents: [],
    emergencies: [],
    audit: [],
    departments: [],
    tasks: [],
    announcements: [],
    expenses: [],
    settings: { departmentsEnabled: false, chiefDoctorId: null },
    traffic: { visitors: 0, pageViews: 0 }
  };
}

if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify(initialDb(), null, 2));

function readDb() {
  let db;
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { db = initialDb(); }
  for (const collection of ['users', 'appointments', 'vitals', 'prescriptions', 'payments', 'consents', 'emergencies', 'audit', 'departments', 'tasks', 'announcements', 'expenses']) {
    if (!Array.isArray(db[collection])) db[collection] = [];
  }
  if (!db.settings || typeof db.settings !== 'object') db.settings = { departmentsEnabled: false, chiefDoctorId: null };
  if (!db.traffic || typeof db.traffic !== 'object') db.traffic = { visitors: 0, pageViews: 0 };
  if (!db.users.some(u => u.role === 'admin')) {
    db.users.unshift({ id: 'USR-ADMIN-001', role: 'admin', firstName: 'Clinic', lastName: 'Administrator', email: 'admin@beulah.test', passwordHash: hashPassword('Admin123!'), adminId: 'ADMIN-001' });
  }
  return db;
}

function writeDb(db) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

function audit(db, actor, action, target = '') {
  db.audit.push({ id: id('AUD'), actor, action, target, at: now() });
  if (db.audit.length > 5000) db.audit = db.audit.slice(-5000);
}

const sessions = new Map();
function getCookie(req, name) {
  const match = new RegExp(`(?:^|;\\s*)${name.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}=([^;]+)`).exec(req.headers.cookie || '');
  return match ? match[1] : null;
}
function setSession(res, user) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { userId: user.id, expires: Date.now() + 8 * 60 * 60 * 1000 });
  res.setHeader('Set-Cookie', `beulah_sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`);
}
function clearSession(res, req) {
  const sid = getCookie(req, 'beulah_sid');
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'beulah_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}
function currentUser(req, db) {
  const sid = getCookie(req, 'beulah_sid');
  if (!sid) return null;
  const session = sessions.get(sid);
  if (!session || session.expires < Date.now()) { if (session) sessions.delete(sid); return null; }
  return db.users.find(user => user.id === session.userId) || null;
}
function publicUser(user) {
  if (!user) return null;
  const result = { id: user.id, role: user.role, firstName: user.firstName, lastName: user.lastName };
  if (user.role !== 'patient') result.email = user.email;
  if (user.role === 'patient') {
    result.cardNumber = cardNumberOf(user);
    result.cardType = user.cardType;
    result.familyCardNumber = user.familyCardNumber || '';
    result.cardName = user.cardName || '';
  }
  if (user.role === 'staff') result.staffId = user.staffId;
  if (user.role === 'doctor') result.doctorId = user.doctorId;
  if (user.role === 'admin') result.adminId = user.adminId;
  result.active = user.active !== false;
  result.mustReset = !!user.mustReset;
  return result;
}
function cardNumberOf(patient) { return String(patient.cardNumber || patient.patientId || '').toUpperCase(); }

function sendJSON(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1024 * 1024) { reject(new Error('Request too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}
const hasRole = (user, roles) => !!user && roles.includes(user.role);

function patientRecord(db, patient) {
  return {
    ...publicUser(patient),
    phone: patient.phone || '',
    dob: patient.dob || '',
    sex: patient.sex || '',
    emergencyContact: patient.emergencyContact || '',
    createdAt: patient.createdAt || '',
    createdByStaffId: patient.createdByStaffId || '',
    familyMembers: patient.familyCardNumber ? db.users.filter(u => u.role === 'patient' && u.familyCardNumber === patient.familyCardNumber).map(publicUser) : [],
    appointments: db.appointments.filter(a => a.patientUserId === patient.id),
    vitals: db.vitals.filter(v => v.patientUserId === patient.id).map(v => {
      const recorder = db.users.find(u => u.id === v.recordedBy);
      return { ...v, recordedByName: recorder ? `${recorder.firstName} ${recorder.lastName}` : 'Unknown', recordedByStaffId: recorder?.staffId || 'N/A', recordedByRole: recorder?.role || '' };
    }),
    prescriptions: db.prescriptions.filter(p => p.patientUserId === patient.id).map(p => ({ ...p, doctorName: (() => { const d = db.users.find(u => u.id === p.prescribedBy); return d ? `${d.firstName} ${d.lastName}` : 'Unknown'; })() })),
    payments: db.payments.filter(p => p.patientUserId === patient.id).map(p => ({ ...p, recordedByName: (() => { const r = db.users.find(u => u.id === p.recordedBy); return r ? `${r.firstName} ${r.lastName}` : 'Unknown'; })() })),
    consents: db.consents.filter(c => c.patientUserId === patient.id)
  };
}

async function api(req, res, pathname) {
  const db = readDb();
  const user = currentUser(req, db);
  try {
    if (req.method === 'POST' && pathname === '/api/auth/login') {
      const b = await parseBody(req);
      const portal = clean(b.role, 30);
      const identifier = clean(b.identifier || b.email, 200).toLowerCase();
      let found;
      if (portal === 'patient') {
        const cardType = clean(b.cardType, 20);
        if (!['Personal', 'Family'].includes(cardType)) return sendJSON(res, 400, { error: 'Choose Personal or Family Card.' });
        found = db.users.find(u => {
          if (u.role !== 'patient' || u.cardType !== cardType) return false;
          const numberMatches = cardType === 'Family'
            ? String(u.familyCardNumber || '').toLowerCase() === identifier
            : String(u.cardNumber || '').toLowerCase() === identifier;
          return numberMatches;
        });
      } else {
        found = db.users.find(u => u.role === portal && (u.email || '').toLowerCase() === identifier && verifyPassword(b.password || '', u.passwordHash));
      }
      if (!found) return sendJSON(res, 401, { error: 'Invalid login details or portal.' });
      if (found.active === false) return sendJSON(res, 403, { error: 'This account has been deactivated. Please contact the Administrator.' });
      setSession(res, found); audit(db, found.id, 'LOGIN'); writeDb(db);
      return sendJSON(res, 200, { user: publicUser(found), mustReset: !!found.mustReset });
    }
    if (req.method === 'POST' && pathname === '/api/auth/logout') { clearSession(res, req); return sendJSON(res, 200, { ok: true }); }
    if (req.method === 'GET' && pathname === '/api/me') return sendJSON(res, 200, { user: publicUser(user) });
    if (!user) return sendJSON(res, 401, { error: 'Please sign in.' });

    if (req.method === 'GET' && pathname === '/api/patient/dashboard' && user.role === 'patient') return sendJSON(res, 200, patientRecord(db, user));

    if (req.method === 'POST' && pathname === '/api/appointments' && user.role === 'patient') {
      const b = await parseBody(req);
      if (!clean(b.date) || !clean(b.type) || !clean(b.reason)) return sendJSON(res, 400, { error: 'Date, type and reason are required.' });
      const appointment = { id: id('APT'), patientUserId: user.id, patientId: cardNumberOf(user), date: clean(b.date, 100), type: clean(b.type, 50), reason: clean(b.reason, 2500), status: 'Pending', operation: clean(b.type) === 'Operation', createdAt: now() };
      db.appointments.push(appointment); audit(db, user.id, 'APPOINTMENT_CREATED', appointment.id); writeDb(db); return sendJSON(res, 201, { appointment });
    }

    if (req.method === 'GET' && pathname === '/api/staff/queue' && hasRole(user, ['staff', 'doctor', 'admin'])) {
      const patients = db.users.filter(u => u.role === 'patient').map(u => publicUser(u));
      const appointments = db.appointments.map(a => ({ ...a, patient: publicUser(db.users.find(p => p.id === a.patientUserId)), consent: !!db.consents.find(c => c.appointmentId === a.id) }));
      return sendJSON(res, 200, { patients, appointments, emergencies: db.emergencies });
    }

    if (req.method === 'GET' && pathname.startsWith('/api/staff/patient/') && hasRole(user, ['staff', 'doctor', 'admin'])) {
      const patientId = decodeURIComponent(pathname.split('/').pop());
      const patient = db.users.find(p => p.role === 'patient' && p.id === patientId);
      if (!patient) return sendJSON(res, 404, { error: 'Patient not found.' });
      return sendJSON(res, 200, { patient: patientRecord(db, patient) });
    }

    if (req.method === 'POST' && pathname === '/api/staff/register-patient' && hasRole(user, ['staff'])) {
      const b = await parseBody(req);
      const firstName = clean(b.firstName, 80);
      const lastName = clean(b.lastName, 80);
      const cardType = clean(b.cardType, 20);
      const cardNumber = clean(b.cardNumber, 80).toUpperCase();
      let cardName = clean(b.cardName, 160);
      if (!firstName || !lastName || !['Personal', 'Family'].includes(cardType) || !cardNumber || !cardName) {
        return sendJSON(res, 400, { error: 'First name, last name, card type, card number and card name are required.' });
      }
      if (cardType === 'Personal') {
        const exists = db.users.some(p => p.role === 'patient' && p.cardType === 'Personal' && cardNumberOf(p) === cardNumber);
        if (exists) return sendJSON(res, 409, { error: 'That Personal Card Number already exists.' });
      } else {
        const existingFamily = db.users.find(p => p.role === 'patient' && p.cardType === 'Family' && String(p.familyCardNumber).toUpperCase() === cardNumber);
        if (!existingFamily && !b.createFamily) return sendJSON(res, 404, { error: 'That Family Card Number does not exist. Create the family card first or enter an existing Family Card Number.' });
        if (existingFamily) cardName = existingFamily.cardName || cardName;
      }
      const patient = {
        id: id('USR'), role: 'patient', firstName, lastName,
        patientId: id('PAT'), cardNumber, cardType,
        cardName, familyCardNumber: cardType === 'Family' ? cardNumber : '',
        phone: clean(b.phone, 50), dob: clean(b.dob, 30), sex: clean(b.sex, 30),
        emergencyContact: clean(b.emergencyContact, 500), createdAt: now(),
        createdByStaffId: user.staffId || user.id, mustReset: true
      };
      db.users.push(patient);
      audit(db, user.id, 'PATIENT_REGISTERED_BY_STAFF', `${cardType}:${cardNumber}`);
      writeDb(db);
      return sendJSON(res, 201, { patient: patientRecord(db, patient), message: `Patient registered successfully. ${cardType} Card Number: ${cardNumber}.` });
    }

    if (req.method === 'POST' && pathname === '/api/staff/lookup-card' && hasRole(user, ['staff', 'doctor', 'admin'])) {
      const b = await parseBody(req);
      const cardType = clean(b.cardType, 20);
      const cardNumber = clean(b.cardNumber, 80).toUpperCase();
      if (!['Personal', 'Family'].includes(cardType) || !cardNumber) return sendJSON(res, 400, { error: 'Enter Card Number and choose Card Type.' });
      const matches = db.users.filter(p => p.role === 'patient' && p.cardType === cardType && (cardType === 'Family' ? String(p.familyCardNumber).toUpperCase() === cardNumber : cardNumberOf(p) === cardNumber));
      if (!matches.length) return sendJSON(res, 404, { error: 'No patient was found for that Card Number and Card Type.' });
      return sendJSON(res, 200, { cardType, cardNumber, cardName: matches[0].cardName || '', patients: matches.map(p => patientRecord(db, p)) });
    }

    if (req.method === 'POST' && pathname === '/api/vitals' && hasRole(user, ['staff', 'doctor'])) {
      const b = await parseBody(req);
      const patient = db.users.find(p => p.role === 'patient' && (b.patientUserId ? p.id === clean(b.patientUserId, 100) : p.cardType === clean(b.cardType, 20) && (p.cardType === 'Family' ? String(p.familyCardNumber).toUpperCase() === clean(b.cardNumber, 80).toUpperCase() : cardNumberOf(p) === clean(b.cardNumber, 80).toUpperCase())));
      if (!patient) return sendJSON(res, 404, { error: 'Patient record not found.' });
      const vital = { id: id('VIT'), patientUserId: patient.id, patientId: cardNumberOf(patient), recordedBy: user.id, recordedAt: now(), temperature: clean(b.temperature, 40), bloodPressure: clean(b.bloodPressure, 40), pulse: clean(b.pulse, 40), respiratoryRate: clean(b.respiratoryRate, 40), spo2: clean(b.spo2, 40), weight: clean(b.weight, 40), notes: clean(b.notes, 1500) };
      db.vitals.push(vital); audit(db, user.id, 'VITALS_RECORDED', patient.patientId); writeDb(db); return sendJSON(res, 201, { vitals: vital });
    }

    if (req.method === 'POST' && pathname === '/api/payments' && hasRole(user, ['staff', 'doctor'])) {
      const b = await parseBody(req);
      const patient = db.users.find(p => p.role === 'patient' && (b.patientUserId ? p.id === clean(b.patientUserId, 100) : p.cardType === clean(b.cardType, 20) && (p.cardType === 'Family' ? String(p.familyCardNumber).toUpperCase() === clean(b.cardNumber, 80).toUpperCase() : cardNumberOf(p) === clean(b.cardNumber, 80).toUpperCase())));
      const amount = Number(b.amount);
      if (!patient) return sendJSON(res, 404, { error: 'Patient record not found.' });
      if (!Number.isFinite(amount) || amount < 0) return sendJSON(res, 400, { error: 'Enter a valid amount.' });
      const payment = { id: id('PAY'), patientUserId: patient.id, patientId: cardNumberOf(patient), recordedBy: user.id, service: clean(b.service, 200), amount, method: clean(b.method, 50), status: clean(b.status, 50), reference: clean(b.reference, 200), paidAt: now() };
      db.payments.push(payment); audit(db, user.id, 'PAYMENT_RECORDED', payment.id); writeDb(db); return sendJSON(res, 201, { payment });
    }

    if (req.method === 'POST' && pathname === '/api/prescriptions' && user.role === 'doctor') {
      const b = await parseBody(req);
      const patient = db.users.find(p => p.role === 'patient' && (b.patientUserId ? p.id === clean(b.patientUserId, 100) : p.cardType === clean(b.cardType, 20) && (p.cardType === 'Family' ? String(p.familyCardNumber).toUpperCase() === clean(b.cardNumber, 80).toUpperCase() : cardNumberOf(p) === clean(b.cardNumber, 80).toUpperCase())));
      if (!patient) return sendJSON(res, 404, { error: 'Patient record not found.' });
      if (!clean(b.drugName) || !clean(b.dosage) || !clean(b.frequency)) return sendJSON(res, 400, { error: 'Drug name, dosage and frequency are required.' });
      const prescription = { id: id('RX'), patientUserId: patient.id, patientId: cardNumberOf(patient), prescribedBy: user.id, doctorId: user.doctorId, drugName: clean(b.drugName, 200), dosage: clean(b.dosage, 100), frequency: clean(b.frequency, 100), duration: clean(b.duration, 100), instructions: clean(b.instructions, 1500), prescribedAt: now() };
      db.prescriptions.push(prescription); audit(db, user.id, 'PRESCRIPTION_CREATED', prescription.id); writeDb(db); return sendJSON(res, 201, { prescription });
    }

    if (req.method === 'POST' && pathname.startsWith('/api/appointments/') && user.role === 'doctor') {
      const appointmentId = pathname.split('/').pop(); const b = await parseBody(req); const appointment = db.appointments.find(a => a.id === appointmentId);
      if (!appointment) return sendJSON(res, 404, { error: 'Appointment not found.' });
      if (!['Pending', 'Confirmed', 'Completed', 'Cancelled'].includes(b.status)) return sendJSON(res, 400, { error: 'Invalid appointment status.' });
      appointment.status = b.status; audit(db, user.id, 'APPOINTMENT_STATUS_CHANGED', appointment.id); writeDb(db); return sendJSON(res, 200, { appointment });
    }

    if (req.method === 'GET' && pathname === '/api/doctor/dashboard' && user.role === 'doctor') {
      const appointments = db.appointments.map(a => ({ ...a, patient: publicUser(db.users.find(p => p.id === a.patientUserId)) })).sort((a,b) => String(a.date).localeCompare(String(b.date)));
      const tasks = db.tasks.filter(t => t.assigneeId === user.id || t.createdBy === user.id).slice(-100).reverse();
      const announcements = db.announcements.filter(a => ['Everyone','Doctors','HODs'].includes(a.audience)).slice(-50).reverse();
      const doctorDepartments = db.departments.filter(d => Array.isArray(d.memberIds) && d.memberIds.includes(user.id) || d.hodId === user.id);
      const chiefDoctor = db.users.find(d => d.id === db.settings.chiefDoctorId && d.role === 'doctor');
      return sendJSON(res, 200, {
        doctor: publicUser(user),
        isChiefDoctor: !!chiefDoctor && chiefDoctor.id === user.id,
        patients: db.users.filter(u => u.role === 'patient').map(p => patientRecord(db, p)),
        appointments,
        emergencies: db.emergencies,
        tasks,
        announcements,
        departments: doctorDepartments,
        consents: db.consents,
        chiefDoctor: chiefDoctor ? publicUser(chiefDoctor) : null
      });
    }

    if (req.method === 'POST' && pathname === '/api/ai/chat' && ['admin','doctor','staff'].includes(user.role)) {
      const b = await parseBody(req);
      const message = clean(b.message, 4000);
      if (!message) return sendJSON(res, 400, { error: 'Please enter a message.' });
      const apiKey = process.env.OPENAI_API_KEY;
      if (!apiKey) {
        const local = {
          admin: 'Beulah AI is ready, but the AI service is not connected yet. I can still help you navigate the clinic system, but live AI responses require the server AI configuration.',
          doctor: 'Beulah AI is ready for the Doctor Workspace, but the AI service is not connected yet. Live AI responses require the server AI configuration.',
          staff: 'Beulah AI is ready for the Staff Workspace, but the AI service is not connected yet. Live AI responses require the server AI configuration.'
        };
        return sendJSON(res, 200, { reply: local[user.role], configured: false });
      }
      const context = { role: user.role, userId: user.id, name: `${user.firstName} ${user.lastName}`, clinic: 'Beulah Medical Clinic' };
      const instructions = `You are Beulah AI, an assistant inside Beulah Medical Clinic. The current user is ${JSON.stringify(context)}. Respect role permissions. Do not diagnose, prescribe, or make clinical decisions. Do not reveal passwords, secrets, or information outside the user's authorization. Help with administrative, workflow, reporting, navigation, and patient-information summarization only when the user is authorized. If asked to change website content, prepare a draft and ask for Admin approval rather than claiming it was published.`;
      const payload = { model: process.env.OPENAI_MODEL || 'gpt-5.6-luna', instructions, input: message, max_output_tokens: 700 };
      const r = await fetch('https://api.openai.com/v1/responses', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` }, body: JSON.stringify(payload) });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) return sendJSON(res, 502, { error: data.error?.message || 'AI service request failed.' });
      const reply = data.output_text || (data.output || []).flatMap(x => x.content || []).map(x => x.text || '').filter(Boolean).join(' ').trim();
      if (!reply) return sendJSON(res, 502, { error: 'AI service returned no text.' });
      audit(db, user.id, 'AI_CHAT', 'Beulah AI'); writeDb(db);
      return sendJSON(res, 200, { reply, configured: true });
    }

    if (req.method === 'GET' && pathname === '/api/admin/dashboard' && user.role === 'admin') {
      const staff = db.users.filter(u => u.role === 'staff');
      const doctors = db.users.filter(u => u.role === 'doctor');
      return sendJSON(res, 200, { users: db.users.map(publicUser), patients: db.users.filter(u => u.role === 'patient').map(p => patientRecord(db, p)), audit: db.audit.slice(-200).reverse(), appointments: db.appointments, payments: db.payments, departments: db.departments, tasks: db.tasks, announcements: db.announcements.slice(-100).reverse(), expenses: db.expenses.slice(-200).reverse(), settings: db.settings, chiefDoctor: doctors.find(d => d.id === db.settings.chiefDoctorId) ? publicUser(doctors.find(d => d.id === db.settings.chiefDoctorId)) : null, counts: { staff: staff.length, doctors: doctors.length, activeStaff: staff.filter(u => u.active !== false).length, activeDoctors: doctors.filter(u => u.active !== false).length, patients: db.users.filter(u => u.role === 'patient').length } });
    }

    if (req.method === 'GET' && pathname === '/api/admin/control-center' && user.role === 'admin') {
      return sendJSON(res, 200, { users: db.users.filter(u => ['staff','doctor','admin'].includes(u.role)).map(publicUser), departments: db.departments, tasks: db.tasks.slice(-200).reverse(), announcements: db.announcements.slice(-100).reverse(), expenses: db.expenses.slice(-200).reverse(), settings: db.settings, traffic: db.traffic, chiefDoctor: db.users.find(u => u.id === db.settings.chiefDoctorId) ? publicUser(db.users.find(u => u.id === db.settings.chiefDoctorId)) : null });
    }

    if (req.method === 'POST' && pathname === '/api/admin/create-user' && user.role === 'admin') {
      const b = await parseBody(req); const targetRole = ['staff', 'doctor'].includes(clean(b.role)) ? clean(b.role) : '';
      if (!targetRole || !clean(b.firstName) || !clean(b.lastName)) return sendJSON(res, 400, { error: 'Role, first name and last name are required.' });
      const count = db.users.filter(u => u.role === targetRole).length;
      const email = clean(b.email, 200).toLowerCase();
      if (!email || db.users.some(u => u.email === email)) return sendJSON(res, 409, { error: 'That email is already in use.' });
      const temporaryPassword = crypto.randomBytes(8).toString('base64url');
      const employee = { id: id('USR'), role: targetRole, firstName: clean(b.firstName, 80), lastName: clean(b.lastName, 80), email, passwordHash: hashPassword(temporaryPassword), createdAt: now(), mustReset: true, active: true, departmentIds: [] };
      if (targetRole === 'staff') employee.staffId = clean(b.employeeId, 80) || `STAFF-${String(count + 1).padStart(3,'0')}`;
      if (targetRole === 'doctor') employee.doctorId = clean(b.employeeId, 80) || `DOC-${String(count + 1).padStart(3,'0')}`;
      db.users.push(employee); audit(db, user.id, 'USER_CREATED', employee.id); writeDb(db);
      return sendJSON(res, 201, { user: publicUser(employee), temporaryPassword });
    }

    if (req.method === 'POST' && pathname === '/api/admin/user-status' && user.role === 'admin') {
      const b = await parseBody(req); const target = db.users.find(u => u.id === clean(b.userId));
      if (!target || !['staff','doctor'].includes(target.role)) return sendJSON(res, 404, { error: 'Staff or doctor not found.' });
      target.active = b.active !== false;
      audit(db, user.id, target.active ? 'USER_REACTIVATED' : 'USER_DEACTIVATED', target.id); writeDb(db);
      return sendJSON(res, 200, { user: publicUser(target) });
    }

    if (req.method === 'POST' && pathname === '/api/admin/department' && user.role === 'admin') {
      const b = await parseBody(req); const name = clean(b.name, 120);
      if (!name) return sendJSON(res, 400, { error: 'Department name is required.' });
      if (db.departments.some(d => d.name.toLowerCase() === name.toLowerCase())) return sendJSON(res, 409, { error: 'That department already exists.' });
      const department = { id: id('DEPT'), name, type: clean(b.type, 50) || 'Custom', hodId: clean(b.hodId) || null, active: true, modules: Array.isArray(b.modules) ? b.modules.map(x => clean(x,60)).filter(Boolean).slice(0,30) : ['Dashboard','Tasks','Documents','Submissions','Reports','Statistics'], createdAt: now(), createdBy: user.id };
      db.departments.push(department);
      if (department.hodId) { const hod = db.users.find(u => u.id === department.hodId && ['staff','doctor'].includes(u.role)); if (hod) { hod.departmentIds = Array.isArray(hod.departmentIds) ? hod.departmentIds : []; if (!hod.departmentIds.includes(department.id)) hod.departmentIds.push(department.id); hod.hodDepartmentIds = Array.isArray(hod.hodDepartmentIds) ? hod.hodDepartmentIds : []; if (!hod.hodDepartmentIds.includes(department.id)) hod.hodDepartmentIds.push(department.id); } }
      audit(db, user.id, 'DEPARTMENT_CREATED', department.id); writeDb(db); return sendJSON(res, 201, { department });
    }

    if (req.method === 'POST' && pathname === '/api/admin/department-assign' && user.role === 'admin') {
      const b = await parseBody(req); const department = db.departments.find(d => d.id === clean(b.departmentId)); const target = db.users.find(u => u.id === clean(b.userId) && ['staff','doctor'].includes(u.role));
      if (!department || !target) return sendJSON(res, 404, { error: 'Department or team member not found.' });
      target.departmentIds = Array.isArray(target.departmentIds) ? target.departmentIds : []; if (!target.departmentIds.includes(department.id)) target.departmentIds.push(department.id);
      if (b.isHod) { department.hodId = target.id; target.hodDepartmentIds = Array.isArray(target.hodDepartmentIds) ? target.hodDepartmentIds : []; if (!target.hodDepartmentIds.includes(department.id)) target.hodDepartmentIds.push(department.id); }
      audit(db, user.id, 'DEPARTMENT_MEMBER_ASSIGNED', `${department.id}:${target.id}`); writeDb(db); return sendJSON(res, 200, { department, user: publicUser(target) });
    }

    if (req.method === 'POST' && pathname === '/api/admin/chief-doctor' && user.role === 'admin') {
      const b = await parseBody(req); const doctor = db.users.find(u => u.id === clean(b.doctorId) && u.role === 'doctor');
      if (!doctor) return sendJSON(res, 404, { error: 'Doctor not found.' });
      db.settings.chiefDoctorId = doctor.id; audit(db, user.id, 'CHIEF_DOCTOR_ASSIGNED', doctor.id); writeDb(db); return sendJSON(res, 200, { doctor: publicUser(doctor) });
    }

    if (req.method === 'POST' && pathname === '/api/admin/settings' && user.role === 'admin') {
      const b = await parseBody(req); if (typeof b.departmentsEnabled === 'boolean') db.settings.departmentsEnabled = b.departmentsEnabled; audit(db, user.id, 'ADMIN_SETTINGS_UPDATED', 'departmentsEnabled'); writeDb(db); return sendJSON(res, 200, { settings: db.settings });
    }

    if (req.method === 'POST' && pathname === '/api/admin/announcement' && user.role === 'admin') {
      const b = await parseBody(req); if (!clean(b.title) || !clean(b.message)) return sendJSON(res, 400, { error: 'Title and message are required.' }); const item = { id:id('ANN'), title:clean(b.title,160), message:clean(b.message,3000), audience:clean(b.audience,80)||'Everyone', createdBy:user.id, createdAt:now() }; db.announcements.push(item); audit(db,user.id,'ANNOUNCEMENT_CREATED',item.id); writeDb(db); return sendJSON(res,201,{announcement:item});
    }

    if (req.method === 'POST' && pathname === '/api/admin/task' && user.role === 'admin') {
      const b=await parseBody(req); if(!clean(b.title)||!clean(b.assigneeId)) return sendJSON(res,400,{error:'Task title and assignee are required.'}); const assignee=db.users.find(u=>u.id===clean(b.assigneeId)&&['staff','doctor','admin'].includes(u.role)); if(!assignee) return sendJSON(res,404,{error:'Assignee not found.'}); const task={id:id('TASK'),title:clean(b.title,180),description:clean(b.description,2500),assigneeId:assignee.id,departmentId:clean(b.departmentId)||null,priority:clean(b.priority,30)||'Normal',status:'Pending',createdBy:user.id,createdAt:now()}; db.tasks.push(task); audit(db,user.id,'TASK_CREATED',task.id); writeDb(db); return sendJSON(res,201,{task});
    }

    if (req.method === 'POST' && pathname === '/api/admin/expense' && user.role === 'admin') {
      const b=await parseBody(req); const amount=Number(b.amount); if(!Number.isFinite(amount)||amount<0||!clean(b.description)) return sendJSON(res,400,{error:'Valid amount and description are required.'}); const expense={id:id('EXP'),amount,description:clean(b.description,250),departmentId:clean(b.departmentId)||null,createdAt:now(),createdBy:user.id}; db.expenses.push(expense); audit(db,user.id,'EXPENSE_RECORDED',expense.id); writeDb(db); return sendJSON(res,201,{expense});
    }

    if (req.method === 'POST' && pathname === '/api/admin/traffic' && user.role === 'admin') {
      const b=await parseBody(req); db.traffic.visitors=Math.max(0,Number(b.visitors)||0); db.traffic.pageViews=Math.max(0,Number(b.pageViews)||0); writeDb(db); return sendJSON(res,200,{traffic:db.traffic});
    }

    if (req.method === 'POST' && pathname === '/api/auth/change-password') {
      const b = await parseBody(req); if (!clean(b.newPassword) || String(b.newPassword).length < 8) return sendJSON(res, 400, { error: 'New password must contain at least 8 characters.' });
      if (!verifyPassword(b.currentPassword || '', user.passwordHash)) return sendJSON(res, 400, { error: 'Current password is incorrect.' });
      user.passwordHash = hashPassword(b.newPassword); user.mustReset = false; audit(db, user.id, 'PASSWORD_CHANGED'); writeDb(db); return sendJSON(res, 200, { ok: true });
    }

    if (req.method === 'POST' && pathname === '/api/emergency') {
      const b = await parseBody(req); if (!clean(b.name) || !clean(b.phone) || !clean(b.condition)) return sendJSON(res, 400, { error: 'Please complete the emergency form.' });
      const emergency = { id: id('EMG'), name: clean(b.name, 120), phone: clean(b.phone, 60), condition: clean(b.condition, 2500), patientUserId: user.role === 'patient' ? user.id : null, createdAt: now(), status: 'New' };
      db.emergencies.push(emergency); audit(db, user.id, 'EMERGENCY_REQUEST_CREATED', emergency.id); writeDb(db); return sendJSON(res, 201, { message: 'Emergency request sent to the clinic dashboard.' });
    }

    return sendJSON(res, 404, { error: 'Endpoint not found.' });
  } catch (error) {
    console.error(error);
    return sendJSON(res, 500, { error: 'The server encountered an error.' });
  }
}

function serveStatic(req, res) {
  let pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname === '/') pathname = '/index.html';
  const filePath = path.normalize(path.join(PUBLIC_DIR, pathname));
  if (!filePath.startsWith(PUBLIC_DIR)) return sendJSON(res, 403, { error: 'Forbidden' });
  fs.readFile(filePath, (error, data) => {
    if (error) return sendJSON(res, 404, { error: 'File not found.' });
    const ext = path.extname(filePath);
    const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.json': 'application/json' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream', 'Cache-Control': 'no-store, no-cache, must-revalidate' }); res.end(data);
  });
}

http.createServer((req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname.startsWith('/api/')) api(req, res, pathname); else serveStatic(req, res);
}).listen(PORT, HOST, () => console.log(`Beulah Medical Clinic running at http://localhost:${PORT}`));
