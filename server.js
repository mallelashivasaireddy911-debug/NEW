const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const sessions = new Map();

const generateToken = () => crypto.randomBytes(32).toString('hex');
const generateSessionId = () => crypto.randomBytes(8).toString('hex');

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
      secretMessage: null,
      secretMessageExpiresAt: null,
    });
  }
  return sessions.get(id);
};

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/session/:sessionId', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

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

app.get('/api/session/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);
  const isHolder = token === session.holderToken;

  let status = 'pending';
  if (session.customer.emailApproved) {
    status = session.codeVerified ? 'verified' : 'code_entry';
  }

  res.json({
    sessionId,
    isHolder,
    status,
    customer: { email: session.customer.email, emailApproved: session.customer.emailApproved },
    codeAttempts: session.codeAttempts,
    maxCodeAttempts: session.maxCodeAttempts,
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
  res.json({ message: 'Email received. Waiting for holder approval.' });
});

app.post('/api/session/:sessionId/approve-customer', (req, res) => {
  const { sessionId } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);
  if (token !== session.holderToken) return res.status(401).json({ error: 'Unauthorized' });

  session.customer.emailApproved = true;
  io.to(`session-${sessionId}`).emit('customer-approved', {});
  res.json({ message: 'Customer approved' });
});

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

app.post('/api/session/:sessionId/send-message', (req, res) => {
  const { sessionId } = req.params;
  const { message } = req.body;
  const token = req.headers.authorization?.split(' ')[1];
  const session = getSession(sessionId);

  if (token !== session.holderToken) return res.status(401).json({ error: 'Unauthorized' });
  if (!session.codeVerified) return res.status(400).json({ error: 'Customer not verified' });

  session.secretMessage = message;
  session.secretMessageExpiresAt = new Date(Date.now() + 60 * 1000);
  io.to(`session-${sessionId}`).emit('secret-message', { message, expiresIn: 60 });
  res.json({ message: 'Message sent!' });
});

io.on('connection', (socket) => {
  socket.on('join-session', (sessionId) => socket.join(`session-${sessionId}`));
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
