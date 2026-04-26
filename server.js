const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// Middleware
app.use(cors());
app.use(express.json());

// No-cache headers
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, '.')));

// ============ STORAGE ============
const sessions = new Map();

// ============ UTILITIES ============
const generateToken = () => crypto.randomBytes(32).toString('hex');
const generateSessionId = () => crypto.randomBytes(8).toString('hex');

const getSession = (id) => {
  if (!sessions.has(id)) {
    sessions.set(id, {
      id,
      holderToken: generateToken(),
      secretCode: null,
      customer: { email: null, emailApproved: false },
      customerCode: null,    // Code submitted by customer (shown to holder)
      codeApproved: false,   // Holder manually approved
      codeRejected: false,   // Holder rejected (customer can retry)
      secretMessage: null,
      secretMessageExpiresAt: null,
    });
  }
  return sessions.get(id);
};

// ============ STATUS HELPER ============
const deriveStatus = (session) => {
  if (session.codeApproved) return 'verified';
  if (session.customerCode && !session.codeRejected) return 'pending_code_approval';
  if (session.customer.emailApproved) return 'code_entry';
  if (session.customer.email) return 'pending_approval';
  return 'pending';
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
    res.json({ sessionId, holderToken: session.holderToken });
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

    const response = {
      sessionId,
      isHolder,
      status: deriveStatus(session),
      customer: {
        email: session.customer.email,
        emailApproved: session.customer.emailApproved,
      },
      secretMessage: session.secretMessage,
      secretMessageExpiresAt: session.secretMessageExpiresAt,
    };

    // Only expose submitted code to holder
    if (isHolder && session.customerCode) {
      response.customerCode = session.customerCode;
    }

    res.json(response);
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

// Holder approves customer email
app.post('/api/session/:sessionId/approve-customer', (req, res) => {
  try {
    const { sessionId } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    const session = getSession(sessionId);

    if (token !== session.holderToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    session.customer.emailApproved = true;

    console.log(`[+] Email approved for: ${session.customer.email}`);
    io.to(`session-${sessionId}`).emit('customer-approved', {});

    res.json({ message: 'Customer approved. Customer will now be prompted for code.' });
  } catch (err) {
    console.error('Error approving customer:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Customer submits secret code (no auto-compare; holder decides)
app.post('/api/session/:sessionId/submit-code', (req, res) => {
  try {
    const { sessionId } = req.params;
    const { code } = req.body;
    const session = getSession(sessionId);

    if (!session.customer.emailApproved) {
      return res.status(400).json({ error: 'Email not approved yet' });
    }

    if (!code || code.trim().length === 0) {
      return res.status(400).json({ error: 'Code is required' });
    }

    session.customerCode = code.toUpperCase().trim();
    session.codeRejected = false;

    console.log(`[+] Customer submitted code — waiting for holder decision`);
    // Notify ONLY the holder (not the customer — they just wait)
    io.to(`session-${sessionId}`).emit('customer-submitted-code', {
      code: session.customerCode,
    });

    res.json({ message: 'Code submitted. Waiting for holder to verify.' });
  } catch (err) {
    console.error('Error submitting code:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Holder approves customer's code
app.post('/api/session/:sessionId/approve-code', (req, res) => {
  try {
    const { sessionId } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    const session = getSession(sessionId);

    if (token !== session.holderToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!session.customerCode) {
      return res.status(400).json({ error: 'No code submitted by customer yet' });
    }

    session.codeApproved = true;
    session.codeRejected = false;

    console.log(`[+] Code approved by holder`);
    io.to(`session-${sessionId}`).emit('code-approved', {});

    res.json({ message: 'Code approved. Session verified.' });
  } catch (err) {
    console.error('Error approving code:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Holder rejects customer's code (customer can retry)
app.post('/api/session/:sessionId/reject-code', (req, res) => {
  try {
    const { sessionId } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    const session = getSession(sessionId);

    if (token !== session.holderToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    session.codeRejected = true;
    session.customerCode = null; // Clear so customer can submit again

    console.log(`[-] Code rejected by holder — customer retry allowed`);
    io.to(`session-${sessionId}`).emit('code-rejected', {});

    res.json({ message: 'Code rejected. Customer can retry.' });
  } catch (err) {
    console.error('Error rejecting code:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Holder sends final secret message
app.post('/api/session/:sessionId/send-message', (req, res) => {
  try {
    const { sessionId } = req.params;
    const { message } = req.body;
    const token = req.headers.authorization?.split(' ')[1];
    const session = getSession(sessionId);

    if (token !== session.holderToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!session.codeApproved) {
      return res.status(400).json({ error: 'Customer not verified yet' });
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

// ============ NEW: RESTART SESSION - RESET FOR CUSTOMER ============
app.post('/api/session/:sessionId/restart', (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = getSession(sessionId);

    // Reset ONLY customer data (keep session, code, holder token)
    session.customer = { email: null, emailApproved: false };
    session.customerCode = null;
    session.codeApproved = false;
    session.codeRejected = false;
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
    console.log(`[+] Socket joined session: ${sessionId}`);
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

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ============ START SERVER ============

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║           🔐 SECRET VERIFY - V16 (With Restart)           ║
║                                                            ║
║  Flow: Email → Holder Approves Email → Customer Enters    ║
║        Code → Holder Approves/Rejects → Secret Message    ║
║        → Message Expires → RESTART CAPABILITY ✨           ║
║                                                            ║
║  No email sending. All decisions made manually by holder. ║
║  Server running on port: ${PORT}                              ║
║  Status: Ready ✅                                          ║
╚════════════════════════════════════════════════════════════╝
  `);
});

module.exports = server;
