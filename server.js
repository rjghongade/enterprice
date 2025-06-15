import express from 'express';
import cors from 'cors';
import mysql from 'mysql2';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
const SECRET = process.env.JWT_SECRET;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN;

// CORS & JSON body parsing
app.use(cors({ origin: CLIENT_ORIGIN }));
app.use(express.json());

// MySQL connection setup
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect(err => {
  if (err) {
    console.error('❌ MySQL connection error:', err.message);
    process.exit(1);
  }
  console.log('✅ MySQL Connected');
});

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// Public: login route
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const query = 'SELECT id, name, email, password, role FROM users WHERE email = ?';

  db.query(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const payload = { id: user.id, role: user.role };
    const token = jwt.sign(payload, SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  });
});

// Secure API routes
const allowedTables = new Set([
  'alerts', 'analyst_logs', 'analyst_soar', 'AnomaliLog', 'app_events',
  'av_logs_soar', 'case_incident_map_soar', 'case_soar', 'case_timeline_soar',
  'cloud_alerts_xdr', 'collaboration_log_soar', 'edr_alerts', 'edr_analyst_logs',
  'edr_endpoints', 'endpoints_xdr', 'exclusion_history_soar', 'forensic_analysis',
  'incident', 'ip_analysis', 'network_alerts_xdr', 'network_logs',
  'phishing_emails_soar', 'ProcessLog1', 'response_action_log_soar', 'threats_xdr',
  'threat_timeline', 'ti_feed_soar', 'USBLog', 'user_activity', 'filelog'
]);

app.get('/api/:table', authenticateToken, (req, res) => {
  const table = req.params.table;
  if (!allowedTables.has(table)) {
    return res.status(400).json({ error: 'Invalid table name' });
  }

  const userId = req.user.id;
  const sql = `SELECT * FROM \`${table}\` WHERE user_id = ?`;
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error(`❌ DB query error (${table}):`, err.message);
      return res.status(500).json({ error: 'Database query failed' });
    }
    res.json(results);
  });
});

app.get('/users/all-users', async (req, res) => {
  try {
    db.query("SELECT * FROM users WHERE role = 'user'", (err, rows) => {
      if (err) {
        console.error("❌ DB error:", err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    });
  } catch (err) {
    res.status(500).json({ error: 'Unexpected error' });
  }
});

// Get single user by ID
app.get('/users/:id', authenticateToken, (req, res) => {
  const userId = req.params.id;

  const sql = 'SELECT id, name, email, role FROM users WHERE id = ?';
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('❌ DB error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    res.json(results[0]);
  });
});


// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});