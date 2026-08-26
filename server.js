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

const LIMITS = { staff: 15, doctor: 5, admin: 3 };

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
    audit: []
  };
}

if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify(initialDb(), null, 2));

function readDb() {
  let db;
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { db = initialDb(); }
  for (const collection of ['users', 'appointments', 'vitals', 'prescriptions', 'payments', 'consents', 'emergencies', 'audit']) {
    if (!Array.isArray(db[collection])) db[collection] = [];
  }
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
      return sendJSON(res, 200, { patients: db.users.filter(u => u.role === 'patient').map(p => patientRecord(db, p)), emergencies: db.emergencies });
    }


    if (req.method === 'GET' && pathname === '/api/admin/dashboard' && user.role === 'admin') {
      return sendJSON(res, 200, { users: db.users.map(publicUser), patients: db.users.filter(u => u.role === 'patient').map(p => patientRecord(db, p)), audit: db.audit.slice(-200).reverse(), appointments: db.appointments, payments: db.payments, limits: LIMITS });
    }

    if (req.method === 'POST' && pathname === '/api/admin/create-user' && user.role === 'admin') {
      const b = await parseBody(req); const targetRole = ['staff', 'doctor'].includes(clean(b.role)) ? clean(b.role) : '';
      if (!targetRole || !clean(b.firstName) || !clean(b.lastName)) return sendJSON(res, 400, { error: 'Role, first name and last name are required.' });
      const count = db.users.filter(u => u.role === targetRole).length;
      if (count >= LIMITS[targetRole]) return sendJSON(res, 409, { error: `The ${targetRole} limit of ${LIMITS[targetRole]} has been reached. Administrator must update the system limit before adding another.` });
      const email = clean(b.email, 200).toLowerCase();
      if (!email || db.users.some(u => u.email === email)) return sendJSON(res, 409, { error: 'That email is already in use.' });
      const temporaryPassword = crypto.randomBytes(8).toString('base64url');
      const employee = { id: id('USR'), role: targetRole, firstName: clean(b.firstName, 80), lastName: clean(b.lastName, 80), email, passwordHash: hashPassword(temporaryPassword), createdAt: now(), mustReset: true };
      if (targetRole === 'staff') employee.staffId = clean(b.employeeId, 80) || `STAFF-${String(count + 1).padStart(3,'0')}`;
      if (targetRole === 'doctor') employee.doctorId = clean(b.employeeId, 80) || `DOC-${String(count + 1).padStart(3,'0')}`;
      db.users.push(employee); audit(db, user.id, 'USER_CREATED', employee.id); writeDb(db);
      return sendJSON(res, 201, { user: publicUser(employee), temporaryPassword });
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
