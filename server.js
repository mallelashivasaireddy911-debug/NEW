const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// Middleware
app.use(cors());
app.use(express.json());

// No-cache headers for all responses
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, '.')));

// Email service
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// ============ STORAGE ============
const sessions = new Map();

// ============ UTILITIES ============
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

// ============ HTML ROUTES ============

app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send('index.html not found');
  }
});

app.get('/session/:sessionId', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send('index.html not found');
  }
});

// ============ API ENDPOINTS ============

// Create new session
app.post('/api/create-session', (req, res) => {
  try {
    const { secretCode } = req.body;
    if (!secretCode || secretCode.trim().length === 0) {
      return res.status(400).json({ error: 'Secret code required' });
    }

    const sessionId = generateSessionId();
    const session = getSession(sessionId);
    session.secretCode = secretCode.toUpperCase().trim();

    console.log(`[+] Session created: ${sessionId}`);
    res.json({
      sessionId,
      holderToken: session.holderToken,
    });
  } catch (err) {
    console.error('Error creating session:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get session state
app.get('/api/session/:sessionId', (req, res) => {
  try {
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
    } else if (session.customer.email) {
      status = 'pending_approval';
    }

    res.json({
      sessionId,
      isHolder,
      status,
      customer: { 
        email: session.customer.email, 
        emailApproved: session.customer.emailApproved 
      },
      codeAttempts: session.codeAttempts,
      maxCodeAttempts: session.maxCodeAttempts,
      secretMessage: session.secretMessage,
      secretMessageExpiresAt: session.secretMessageExpiresAt,
    });
  } catch (err) {
    console.error('Error getting session:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Customer submits email
app.post('/api/session/:sessionId/customer-email', (req, res) => {
  try {
    const { sessionId } = req.params;
    const { email } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const session = getSession(sessionId);
    session.customer.email = email;

    console.log(`[+] Customer email submitted: ${email}`);
    io.to(`session-${sessionId}`).emit('customer-submitted-email', { email });
    
    res.json({ message: 'Email received. Waiting for holder approval.' });
  } catch (err) {
    console.error('Error submitting email:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Holder approves customer
app.post('/api/session/:sessionId/approve-customer', (req, res) => {
  try {
    const { sessionId } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    const session = getSession(sessionId);

    if (token !== session.holderToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    session.customer.emailApproved = true;

    console.log(`[+] Customer approved: ${session.customer.email}`);
    io.to(`session-${sessionId}`).emit('customer-approved', {});
    
    res.json({ message: 'Customer approved' });
  } catch (err) {
    console.error('Error approving customer:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Customer verifies code
app.post('/api/session/:sessionId/verify-code', (req, res) => {
  try {
    const { sessionId } = req.params;
    const { code } = req.body;
    const session = getSession(sessionId);

    if (!session.customer.emailApproved) {
      return res.status(400).json({ error: 'Email not approved yet' });
    }

    session.codeAttempts++;
    const isCorrect = code.toUpperCase().trim() === session.secretCode.toUpperCase().trim();

    console.log(`[${session.codeAttempts}/3] Code attempt - Correct: ${isCorrect}`);
    io.to(`session-${sessionId}`).emit('code-attempt', { 
      attempt: session.codeAttempts, 
      correct: isCorrect 
    });

    if (isCorrect) {
      session.codeVerified = true;
      console.log(`[+] Code verified!`);
      return res.json({ message: 'Code accepted!' });
    }

    if (session.codeAttempts >= session.maxCodeAttempts) {
      console.log(`[-] Code attempts exceeded`);
      return res.status(403).json({ error: 'Maximum attempts exceeded' });
    }

    res.status(400).json({ 
      error: 'Incorrect code', 
      attemptsLeft: session.maxCodeAttempts - session.codeAttempts 
    });
  } catch (err) {
    console.error('Error verifying code:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Holder sends secret value email
app.post('/api/session/:sessionId/send-secret-value', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    const session = getSession(sessionId);

    if (token !== session.holderToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!session.codeVerified) {
      return res.status(400).json({ error: 'Code not verified yet' });
    }

    const secretValue = generateSecretValue();
    session.secretValue = secretValue;
    session.secretValueExpiresAt = new Date(Date.now() + 30 * 1000);

    console.log(`[+] Sending secret value to ${session.customer.email}`);

    // Send email
    try {
      await mailer.sendMail({
        to: session.customer.email,
        subject: '🔐 Your Secret Verification Code',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
              <h1 style="margin: 0;">🔐 Secret Verification</h1>
            </div>
            <div style="background: #f5f5f5; padding: 30px; text-align: center; border-radius: 0 0 10px 10px;">
              <p style="color: #666; margin-bottom: 20px;">Please enter this code to verify your identity:</p>
              <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="font-family: monospace; font-size: 24px; font-weight: bold; color: #667eea; letter-spacing: 2px; margin: 0;">${secretValue}</p>
              </div>
              <p style="color: #e74c3c; font-weight: bold;">⚠️ This code expires in 30 seconds!</p>
              <p style="color: #999; font-size: 12px;">If you didn't request this, please ignore this email.</p>
            </div>
          </div>
        `
      });
      console.log(`[✓] Email sent successfully`);
    } catch (emailErr) {
      console.error('[✗] Email send failed:', emailErr.message);
    }

    io.to(`session-${sessionId}`).emit('secret-value-sent', { expiresIn: 30 });
    res.json({ 
      message: 'Secret value sent to email!', 
      secretValue
    });
  } catch (err) {
    console.error('Error sending secret value:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Customer verifies secret value
app.post('/api/session/:sessionId/verify-value', (req, res) => {
  try {
    const { sessionId } = req.params;
    const { value } = req.body;
    const session = getSession(sessionId);

    if (!session.secretValue) {
      return res.status(400).json({ error: 'No secret value issued' });
    }

    if (new Date() > session.secretValueExpiresAt) {
      console.log(`[-] Secret value expired`);
      return res.status(410).json({ error: 'Secret value expired' });
    }

    const isCorrect = value.toUpperCase().trim() === session.secretValue.toUpperCase().trim();

    if (isCorrect) {
      session.valueVerified = true;
      console.log(`[+] Secret value verified!`);
      io.to(`session-${sessionId}`).emit('customer-verified', {});
      return res.json({ message: 'Verified! Chat unlocked.' });
    }

    console.log(`[-] Incorrect secret value`);
    res.status(400).json({ error: 'Incorrect secret value' });
  } catch (err) {
    console.error('Error verifying value:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Holder sends final message
app.post('/api/session/:sessionId/send-message', (req, res) => {
  try {
    const { sessionId } = req.params;
    const { message } = req.body;
    const token = req.headers.authorization?.split(' ')[1];
    const session = getSession(sessionId);

    if (token !== session.holderToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!session.valueVerified) {
      return res.status(400).json({ error: 'Customer not verified' });
    }

    if (!message || message.trim().length === 0) {
      return res.status(400).json({ error: 'Message cannot be empty' });
    }

    session.secretMessage = message;
    session.secretMessageExpiresAt = new Date(Date.now() + 60 * 1000);

    console.log(`[+] Secret message sent to customer`);
    io.to(`session-${sessionId}`).emit('secret-message', { message, expiresIn: 60 });
    
    res.json({ message: 'Message sent!' });
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ NEW: RESTART SESSION (Reset for customer) ============

// Customer can restart the verification process
app.post('/api/session/:sessionId/restart', (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = getSession(sessionId);

    // Reset customer data only (keep session, code, and holder token)
    session.customer = { email: null, emailApproved: false };
    session.codeAttempts = 0;
    session.codeVerified = false;
    session.secretValue = null;
    session.secretValueExpiresAt = null;
    session.valueVerified = false;
    session.secretMessage = null;
    session.secretMessageExpiresAt = null;

    console.log(`[↻] Session restarted: ${sessionId}`);
    io.to(`session-${sessionId}`).emit('session-restarted', {});
    
    res.json({ message: 'Session restarted. Please submit your email again.' });
  } catch (err) {
    console.error('Error restarting session:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ WEBSOCKET ============

io.on('connection', (socket) => {
  socket.on('join-session', (sessionId) => {
    socket.join(`session-${sessionId}`);
    console.log(`[+] Socket connected to session: ${sessionId}`);
  });

  socket.on('disconnect', () => {
    console.log(`[-] Socket disconnected`);
  });
});

// ============ ERROR HANDLING ============

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ============ START SERVER ============

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║           🔐 SECRET VERIFY - COMPLETE V15                ║
║                                                            ║
║  Holder: Creates session, approves customer, sends secret  ║
║  Customer: Email → Code → Value → Message → Restart       ║
║                                                            ║
║  Server running on port: ${PORT}
║  Environment: ${process.env.NODE_ENV || 'development'}
║  Status: Ready ✅                                          ║
╚════════════════════════════════════════════════════════════╝
  `);
});

module.exports = server;
