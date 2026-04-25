const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

// Force no-cache for index.html to break Railway cache
app.use(express.static(path.join(__dirname), {
  setHeaders: (res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }
}));

// Email service setup
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

const sessions = new Map();

const generateToken = () => crypto.randomBytes(32).toString('hex');
const generateSessionId = () => crypto.randomBytes(8).toString('hex');
const generateSecretValue = () => `SECRET-VALUE-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

const getSession = (id) => {
  if (!sessions.has(id)) {
    sessions.set(id, {
      id,
      holderToken: generateToken(),
      secretCode: null,
      customer: { email: null, emailApproved: false },
      codeAttempts: 0,
      maxCodeAttempts: 3,
      codeVerified: false,
      secretValue: null,
      secretValueExpiresAt: null,
      valueVerified: false,
      secretMessage: null,
      secretMessageExpiresAt: null,
    });
  }
  return sessions.get(id);
};

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/session/:sessionId', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Create session
app.post('/api/create-session', (req, res) => {
  const { secretCode } = req.body;
  if (!secretCode) return res.status(400).json({ error: 'Secret code required' });

  const sessionId = generateSessionId();
  const session = getSession(sessionId);
  session.secretCode = secretCode.toUpperCase().trim();

  res.json({
    sessionId,
    holderToken: session.holderToken,
  });
});

// Get session state
app.get('/api/session/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);
  const isHolder = token === session.holderToken;

  let status = 'pending';
  if (session.customer.emailApproved) {
    if (session.valueVerified) {
      status = 'verified';
    } else if (session.codeVerified) {
      status = 'value_entry';
    } else {
      status = 'code_entry';
    }
  }

  res.json({
    sessionId,
    isHolder,
    status,
    customer: { email: session.customer.email, emailApproved: session.customer.emailApproved },
    codeAttempts: session.codeAttempts,
    maxCodeAttempts: session.maxCodeAttempts,
    secretMessage: session.secretMessage,
    secretMessageExpiresAt: session.secretMessageExpiresAt,
  });
});

// Customer submits email
app.post('/api/session/:sessionId/customer-email', (req, res) => {
  const { sessionId } = req.params;
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  const session = getSession(sessionId);
  session.customer.email = email;
  io.to(`session-${sessionId}`).emit('customer-submitted-email', { email });
  res.json({ message: 'Email received. Waiting for holder approval.' });
});

// Holder approves customer
app.post('/api/session/:sessionId/approve-customer', (req, res) => {
  const { sessionId } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);
  if (token !== session.holderToken) return res.status(401).json({ error: 'Unauthorized' });

  session.customer.emailApproved = true;
  io.to(`session-${sessionId}`).emit('customer-approved', {});
  res.json({ message: 'Customer approved' });
});

// Customer verifies code
app.post('/api/session/:sessionId/verify-code', (req, res) => {
  const { sessionId } = req.params;
  const { code } = req.body;
  const session = getSession(sessionId);

  if (!session.customer.emailApproved) return res.status(400).json({ error: 'Email not approved yet' });

  session.codeAttempts++;
  const isCorrect = code.toUpperCase().trim() === session.secretCode;

  io.to(`session-${sessionId}`).emit('code-attempt', { attempt: session.codeAttempts, correct: isCorrect });

  if (isCorrect) {
    session.codeVerified = true;
    return res.json({ message: 'Code accepted!' });
  }

  if (session.codeAttempts >= session.maxCodeAttempts) {
    return res.status(403).json({ error: 'Maximum attempts exceeded' });
  }
  res.status(400).json({ error: 'Incorrect code', attemptsLeft: session.maxCodeAttempts - session.codeAttempts });
});

// Holder sends secret value email
app.post('/api/session/:sessionId/send-secret-value', async (req, res) => {
  const { sessionId } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);

  if (token !== session.holderToken) return res.status(401).json({ error: 'Unauthorized' });
  if (!session.codeVerified) return res.status(400).json({ error: 'Code not verified yet' });

  const secretValue = generateSecretValue();
  session.secretValue = secretValue;
  session.secretValueExpiresAt = new Date(Date.now() + 30 * 1000);

  // Send email
  try {
    await mailer.sendMail({
      to: session.customer.email,
      subject: '🔐 Your Secret Verification Code',
      html: `
        <h2>Your Secret Verification Code</h2>
        <p>Please enter this code to verify:</p>
        <h1 style="font-family: monospace; letter-spacing: 2px;">${secretValue}</h1>
        <p style="color: red;"><strong>⚠️ This code expires in 30 seconds!</strong></p>
      `
    });
    console.log(`Email sent to ${session.customer.email} with code: ${secretValue}`);
  } catch (err) {
    console.error('Email send error:', err);
    // Still proceed even if email fails (for testing)
  }

  io.to(`session-${sessionId}`).emit('secret-value-sent', { expiresIn: 30 });
  res.json({ message: 'Secret value sent to email!', secretValue }); // Return value for testing
});

// Customer verifies secret value
app.post('/api/session/:sessionId/verify-value', (req, res) => {
  const { sessionId } = req.params;
  const { value } = req.body;
  const session = getSession(sessionId);

  if (!session.secretValue) return res.status(400).json({ error: 'No secret value issued' });
  if (new Date() > session.secretValueExpiresAt) {
    return res.status(410).json({ error: 'Secret value expired' });
  }

  const isCorrect = value.toUpperCase().trim() === session.secretValue.toUpperCase().trim();

  if (isCorrect) {
    session.valueVerified = true;
    io.to(`session-${sessionId}`).emit('customer-verified', {});
    return res.json({ message: 'Verified! Chat unlocked.' });
  }

  res.status(400).json({ error: 'Incorrect secret value' });
});

// Holder sends final message
app.post('/api/session/:sessionId/send-message', (req, res) => {
  const { sessionId } = req.params;
  const { message } = req.body;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);

  if (token !== session.holderToken) return res.status(401).json({ error: 'Unauthorized' });
  if (!session.valueVerified) return res.status(400).json({ error: 'Customer not verified' });

  session.secretMessage = message;
  session.secretMessageExpiresAt = new Date(Date.now() + 60 * 1000);
  io.to(`session-${sessionId}`).emit('secret-message', { message, expiresIn: 60 });
  res.json({ message: 'Message sent!' });
});

// WebSocket connection
io.on('connection', (socket) => {
  socket.on('join-session', (sessionId) => {
    socket.join(`session-${sessionId}`);
  });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`🚀 Secret Verify Server started - V13-COMPLETE`));
