const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const crypto = require('crypto');
const path = require('path');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const sessions = new Map();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

const generateToken = () => crypto.randomBytes(32).toString('hex');
const generateSessionId = () => crypto.randomBytes(8).toString('hex');
const generateSecretValue = () => `SECRET-VALUE-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

const getSession = (id) => {
  if (!sessions.has(id)) {
    sessions.set(id, {
      id,
      holderToken: generateToken(),
      secretCode: null,
      customer: { email: null, emailVerifiedAt: null },
      codeAttempts: 0,
      maxCodeAttempts: 3,
      codeVerifiedAt: null,
      secretValue: null,
      secretValueExpiresAt: null,
      valueVerifiedAt: null,
      secretMessage: null,
      secretMessageExpiresAt: null,
      createdAt: Date.now()
    });
  }
  return sessions.get(id);
};

// ====================== STATIC PAGES ======================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/session/:sessionId', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ====================== API ======================

app.post('/api/create-session', (req, res) => {
  const { secretCode } = req.body;
  if (!secretCode) return res.status(400).json({ error: 'Secret code required' });

  const sessionId = generateSessionId();
  const session = getSession(sessionId);
  session.secretCode = secretCode.toUpperCase().trim();

  res.json({
    sessionId,
    holderToken: session.holderToken,
    shareLink: `https://\( {req.get('host')}/session/ \){sessionId}`
  });
});

app.get('/api/session/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);
  const isHolder = token === session.holderToken;

  let status = 'pending';
  if (session.customer.emailVerifiedAt) {
    status = session.valueVerifiedAt ? 'verified' : (session.codeVerifiedAt ? 'value_entry' : 'code_entry');
  }

  res.json({
    sessionId,
    isHolder,
    status,
    customer: { email: session.customer.email, emailApproved: !!session.customer.emailVerifiedAt },
    codeAttempts: session.codeAttempts,
    maxCodeAttempts: session.maxCodeAttempts,
    messageExpiredAt: session.secretMessageExpiresAt
  });
});

app.post('/api/session/:sessionId/customer-email', (req, res) => {
  const { sessionId } = req.params;
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  const session = getSession(sessionId);
  session.customer.email = email;
  io.to(`session-${sessionId}`).emit('customer-submitted-email', { email });
  res.json({ message: 'Email received. Waiting for holder approval.', status: 'pending_approval' });
});

app.post('/api/session/:sessionId/approve-customer', (req, res) => {
  const { sessionId } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);
  if (token !== session.holderToken) return res.status(401).json({ error: 'Unauthorized' });
  session.customer.emailVerifiedAt = new Date();
  io.to(`session-${sessionId}`).emit('customer-approved', { message: 'Approved! Enter your secret code.' });
  res.json({ message: 'Customer approved' });
});

app.post('/api/session/:sessionId/verify-code', (req, res) => {
  const { sessionId } = req.params;
  const { code } = req.body;
  const session = getSession(sessionId);
  if (!session.customer.emailVerifiedAt) return res.status(400).json({ error: 'Email not approved yet' });

  session.codeAttempts++;
  const isCorrect = code.toUpperCase().trim() === session.secretCode;

  io.to(`session-${sessionId}`).emit('code-attempt', {
    attempt: session.codeAttempts,
    correct: isCorrect,
    attemptsLeft: session.maxCodeAttempts - session.codeAttempts
  });

  if (isCorrect) {
    session.codeVerifiedAt = new Date();
    return res.json({ message: 'Code accepted!', nextStep: 'wait_for_secret_value' });
  }

  if (session.codeAttempts >= session.maxCodeAttempts) {
    return res.status(403).json({ error: 'Maximum attempts exceeded. Contact holder.', attemptsLeft: 0 });
  }
  res.status(400).json({ error: 'Incorrect code', attemptsLeft: session.maxCodeAttempts - session.codeAttempts });
});

app.post('/api/session/:sessionId/send-secret-value', async (req, res) => {
  const { sessionId } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);
  if (token !== session.holderToken) return res.status(401).json({ error: 'Unauthorized' });
  if (!session.codeVerifiedAt) return res.status(400).json({ error: 'Code not verified yet' });

  const secretValue = generateSecretValue();
  session.secretValue = secretValue;
  session.secretValueExpiresAt = new Date(Date.now() + 30 * 1000);

  try {
    await transporter.sendMail({
      to: session.customer.email,
      subject: 'Your Secret Verification Value',
      html: `<h2>Your secret value is:</h2><p style="font-size:24px;font-family:monospace;letter-spacing:4px;">${secretValue}</p><p><strong>Expires in 30 seconds</strong></p>`
    });
    io.to(`session-${sessionId}`).emit('secret-value-sent', { expiresIn: 30 });
    res.json({ message: 'Secret value sent!', secretValue });
  } catch (e) {
    res.status(500).json({ error: 'Failed to send email' });
  }
});

app.post('/api/session/:sessionId/verify-value', (req, res) => {
  const { sessionId } = req.params;
  const { value } = req.body;
  const session = getSession(sessionId);

  if (!session.secretValue || new Date() > session.secretValueExpiresAt) {
    return res.status(410).json({ error: 'Secret value expired' });
  }

  if (value.toUpperCase().trim() === session.secretValue) {
    session.valueVerifiedAt = new Date();
    io.to(`session-${sessionId}`).emit('customer-verified', { status: 'verified' });
    return res.json({ message: 'Verified! Chat unlocked.', status: 'verified' });
  }
  res.status(400).json({ error: 'Incorrect secret value' });
});

app.post('/api/session/:sessionId/send-message', (req, res) => {
  const { sessionId } = req.params;
  const { message } = req.body;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);
  if (token !== session.holderToken) return res.status(401).json({ error: 'Unauthorized' });
  if (!session.valueVerifiedAt) return res.status(400).json({ error: 'Customer not verified' });

  session.secretMessage = message;
  session.secretMessageExpiresAt = new Date(Date.now() + 60 * 1000);

  io.to(`session-${sessionId}`).emit('secret-message', {
    message,
    expiresIn: 60,
    sentAt: new Date().toISOString()
  });
  res.json({ message: 'Message sent!' });
});

// ====================== SOCKET.IO ======================
io.on('connection', (socket) => {
  socket.on('join-session', (sessionId) => {
    socket.join(`session-${sessionId}`);
    const session = getSession(sessionId);
    socket.emit('session-state', { status: session.customer.email ? 'has_email' : 'pending' });
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
