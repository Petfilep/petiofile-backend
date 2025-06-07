require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN,
  credentials: true
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Ensure tables
pool.query(\`
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255),
  email VARCHAR(255) UNIQUE,
  password VARCHAR(255),
  reset_token VARCHAR(255)
);
CREATE TABLE IF NOT EXISTS carts (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  item TEXT,
  quantity INTEGER
);
CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  total NUMERIC,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
\`);

app.post("/api/signup", async (req, res) => {
  const { username, email, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  try {
    await pool.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [username, email, hashed]);
    res.status(201).json({ message: "User registered" });
  } catch {
    res.status(400).json({ message: "Email already exists" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  const user = result.rows[0];
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "2h" });
    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

app.get("/api/profile", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "No token" });
  try {
    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query("SELECT username, email FROM users WHERE id = $1", [decoded.id]);
    res.json(result.rows[0]);
  } catch {
    res.status(403).json({ message: "Invalid token" });
  }
});

app.post("/api/cart/add", async (req, res) => {
  const { token, item, quantity } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await pool.query("INSERT INTO carts (user_id, item, quantity) VALUES ($1, $2, $3)", [decoded.id, item, quantity]);
    res.json({ message: "Item added" });
  } catch {
    res.status(403).json({ message: "Invalid token" });
  }
});

app.get("/api/cart", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query("SELECT item, quantity FROM carts WHERE user_id = $1", [decoded.id]);
    res.json(result.rows);
  } catch {
    res.status(403).json({ message: "Invalid token" });
  }
});

app.post("/api/logout", (req, res) => {
  res.status(200).json({ message: "Logout handled client-side" });
});

// ✅ Added home route
app.get("/", (req, res) => {
  res.json({ message: "Petio API is live!" });
});

app.listen(3000, () => console.log("✅ PetioFile backend running on port 3000"));
