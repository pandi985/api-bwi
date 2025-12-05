require("dotenv").config();
const express = require("express");
const cors = require("cors");
const db = require("./db.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticateToken, authorizeRole } = require("./middleware/authMiddleware.js");

const app = express();
const PORT = process.env.PORT || 3300;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// routes
app.get("/status", (req, res) => {
  res.json({ ok: true, service: "resto-api" });
});

// auth routes
app.post("/auth/register", async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password || password.length < 6) {
    return res.status(400).json({ error: "Username dan password (min 6 char) harus diisi" });
  }
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const sql = "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username";
    const result = await db.query(sql, [username.toLowerCase(), hashedPassword, "user"]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      // kode error unik postgresql
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

app.post("/auth/register-admin", async (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res.status(400).json({ error: "Username dan password (min 6 char) harus diisi" });
  }
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const sql = "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username";
    const result = await db.query(sql, [username.toLowerCase(), hashedPassword, "admin"]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      // kode error unik postgresql
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

app.post("/auth/login", async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const sql = "SELECT * FROM users WHERE username= $1";
    const result = await db.query(sql, [username.toLowerCase()]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }
    const payload = {
      user: { id: user.id, username: user.username, role: user.role },
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login berhasil", token: token });
  } catch (err) {
    next(err);
  }
});

// route get
app.get("/menu", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM resto_jsonb ORDER BY id ASC");
    const formattedData = result.rows.map((item) => ({
      id: item.id,
      details: item.details,
      pricing: {
        base_price: item.pricing.base_price,
        tax: item.pricing.tax,
      },
      stock: item.stock,
    }));

    res.json(formattedData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// route get/id
app.get("/menu/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const result = await db.query("SELECT * FROM resto WHERE id = $1", [id]);
    const formattedData = result.rows.map((item) => ({
      id: item.id,
      details: item.details,
      pricing: {
        base_price: item.pricing.base_price,
        tax: item.pricing.tax,
      },
      stock: item.stock,
    }));

    res.json(formattedData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// route post
app.post("/menu", authenticateToken, async (req, res) => {
  try {
    const { details, pricing, stock } = req.body;
    if (!details || !pricing || !stock) {
      return res.status(400).json({ error: "Data tidak lengkap" });
    }
    const result = await db.query("INSERT INTO resto_jsonb (details, pricing, stock) VALUES ($1, $2, $3) RETURNING *", [details, pricing, stock]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// route put/id
app.put("/menu/:id", [authenticateToken, authorizeRole("admin")], async (req, res) => {
  try {
    const id = req.params.id;
    const { details, pricing, stock } = req.body;

    if (!details || !pricing || !stock) {
      return res.status(400).json({ error: "details, pricing, dan stock wajib diisi" });
    }

    const check = await db.query("SELECT * FROM resto_jsonb WHERE id = $1", [id]);

    if (check.rowCount === 0) {
      return res.status(404).json({ error: "Item tidak ditemukan" });
    }

    const result = await db.query("UPDATE resto_jsonb SET details = $1, pricing = $2, stock = $3 WHERE id = $4 RETURNING *", [details, pricing, stock, id]);

    res.json({
      message: "Item berhasil diupdate",
      Item: result.rows[0],
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ error: "Gagal mengupdate item" });
  }
});

// route delete/id
app.delete("/menu/:id", [authenticateToken, authorizeRole("admin")], async (req, res) => {
  try {
    const id = req.params.id;
    const result = await db.query("DELETE FROM resto_jsonb WHERE id = $1 RETURNING *", [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Item tidak ditemukan" });
    }
    res.json({
      message: "Item berhasil dihapus",
      id: result.rows[0].id,
      details: result.rows[0].details,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// fallback dan error handling
app.use((req, res) => {
  res.status(404).json({ error: "Rute tidak ditemukan" });
});

app.use((err, req, res, next) => {
  console.error(err); // tampilkan error asli
  res.status(500).json({
    error: err.message,
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
