const express = require('express');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://trauma-game-password-default-rtdb.europe-west1.firebasedatabase.app"
});

const db = admin.database();
const app = express();
app.use(cors());
app.use(bodyParser.json());

/*app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && origin !== 'https://trauma2.netlify.app') {
    return res.status(403).json({ success: false, error: 'Forbidden: Invalid origin' });
  }
  next();
});*/

const checkPasswordLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many requests, please slow down.' }
});

app.post('/check-password', checkPasswordLimiter, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ success: false });

  try {
    const snapshot = await db.ref('passwords').once('value');
    const passwords = snapshot.val();
    if (password === passwords.gamePassword) {
      return res.json({ success: true, role: 'game' });
    } else if (password === passwords.adminPassword) {
      return res.json({ success: true, role: 'admin' });
    } else {
      return res.json({ success: false });
    }
  } catch (err) {
    console.error("Error checking password:", err);
    res.status(500).json({ success: false });
  }
});

app.get('/get-passwords', async (req, res) => {
  try {
    const snapshot = await db.ref('passwords').once('value');
    const passwords = snapshot.val();
    if (!passwords) {
      return res.status(404).json({ error: 'Passwords not found' });
    }
    res.json({
      gamePassword: passwords.gamePassword,
      adminPassword: passwords.adminPassword
    });
  } catch (err) {
    console.error('Error fetching passwords:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/set-password', async (req, res) => {
  const { passwordType, newPassword } = req.body;
  if (!passwordType || !newPassword) {
    return res.status(400).json({ success: false, error: 'Missing data' });
  }
  if (!['gamePassword', 'adminPassword'].includes(passwordType)) {
    return res.status(400).json({ success: false, error: 'Invalid password type' });
  }
  try {
    await db.ref(`passwords/${passwordType}`).set(newPassword);
    console.log(`Updated ${passwordType} to: ${newPassword}`);
    res.json({ success: true });
  } catch (err) {
    console.error('Error setting password:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
