require("dotenv").config();
const express = require("express");
const cors = require("cors");
const db = require("./db.js"); // Menggunakan modul pg baru
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticateToken, authorizeRole } = require("./middleware/authMiddleware.js");

const app = express();
const PORT = process.env.PORT || 3300;
const JWT_SECRET = process.env.JWT_SECRET;
// === MIDDLEWARE ===
app.use(cors());
app.use(express.json());
// === DATA MAPPER FUNCTION ===
// Fungsi ini mengubah hasil datar dari SQL menjadi format Nested Object yang diminta
const mapProductToNestedFormat = (product) => {
  return {
    id: product.id,
    details: {
      name: product.name,
      category: product.category,
    },
    pricing: {
      base_price: product.base_price,
      tax: product.tax,
    },
    stock: product.stock,
  };
};
// =============================

// === ROUTES ===
app.get("/status", (req, res) => {
  res.json({ ok: true, service: "resto-api" });
});

// === AUTH ROUTES (Tidak diubah, hanya memastikan integritas) ===
app.post("/auth/register", async (req, res, next) => {
  // ... (Logika Register tidak diubah) ...
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
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

app.post("/auth/register-admin", async (req, res, next) => {
  // ... (Logika Register Admin tidak diubah) ...
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
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

app.post("/auth/login", async (req, res, next) => {
  // ... (Logika Login tidak diubah) ...
  const { username, password } = req.body;
  try {
    const sql = "SELECT * FROM users WHERE username = $1";
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

// ------------------------------------------------------------------
// === RESTO/PRODUCT ROUTES (Diubah untuk format Nested Object) ===
// ------------------------------------------------------------------

// GET All Products
app.get("/resto", async (req, res, next) => {
  // Mengasumsikan tabel 'products' dengan kolom yang relevan
  const sql = `
    SELECT id, name, category, base_price, tax, stock
    FROM products
    ORDER BY id ASC
  `;
  try {
    const result = await db.query(sql); // Menggunakan mapper untuk setiap baris hasil query
    const nestedProducts = result.rows.map(mapProductToNestedFormat);
    res.json(nestedProducts); // Mengirim array Nested Object
  } catch (err) {
    next(err);
  }
});

// GET Product by ID
app.get("/resto/:id", async (req, res, next) => {
  const sql = `
    SELECT id, name, category, base_price, tax, stock
    FROM products
    WHERE id = $1
  `;
  try {
    const result = await db.query(sql, [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Produk tidak ditemukan" });
    } // Menggunakan mapper untuk satu baris hasil query
    const nestedProduct = mapProductToNestedFormat(result.rows[0]);
    res.json(nestedProduct); // Mengirim satu Nested Object
  } catch (err) {
    next(err);
  }
});

// POST Product
app.post("/resto", authenticateToken, async (req, res, next) => {
  const { name, category, base_price, tax, stock } = req.body;
  if (!name || !category || !base_price || !tax || !stock) {
    return res.status(400).json({ error: "name, category, base_price, tax, stock wajib diisi" });
  }

  const sql = `
    INSERT INTO products (name, category, base_price, tax, stock) 
    VALUES ($1, $2, $3, $4, $5) 
    RETURNING id, name, category, base_price, tax, stock
  `;
  try {
    const result = await db.query(sql, [name, category, base_price, tax, stock]); // Menggunakan mapper sebelum mengirim response 201 Created
    const nestedProduct = mapProductToNestedFormat(result.rows[0]);
    res.status(201).json(nestedProduct);
  } catch (err) {
    next(err);
  }
});

// PUT Product
app.put("/resto/:id", [authenticateToken, authorizeRole("admin")], async (req, res, next) => {
  const { name, category, base_price, tax, stock } = req.body;
  const sql = `
    UPDATE products SET 
      name = $1, category = $2, base_price = $3, tax = $4, stock = $5
    WHERE id = $6 
    RETURNING id, name, category, base_price, tax, stock
  `;
  try {
    const result = await db.query(sql, [name, category, base_price, tax, stock, req.params.id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Produk tidak ditemukan" });
    } // Menggunakan mapper
    const nestedProduct = mapProductToNestedFormat(result.rows[0]);
    res.json(nestedProduct);
  } catch (err) {
    next(err);
  }
});

// DELETE Product
app.delete("/resto/:id", [authenticateToken, authorizeRole("admin")], async (req, res, next) => {
  const sql = "DELETE FROM products WHERE id = $1 RETURNING *";
  try {
    const result = await db.query(sql, [req.params.id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Produk tidak ditemukan" });
    }
    res.status(204).send();
  } catch (err) {
    next(err);
  }
});

// === ERROR HANDLER (Opsional, pastikan ini ada di akhir) ===
app.use((req, res, next) => {
  res.status(404).json({ error: "Rute tidak ditemukan" });
});

app.use((err, req, res, next) => {
  console.error("[SERVER ERROR]", err.stack);
  res.status(500).json({ error: "Terjadi kesalahan pada server" });
});
// === START SERVER ===
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server aktif di http://localhost:${PORT}`);
});
