const JWT = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

// middleware autentikasi (yang sudah ada)
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return res
      .status(401)
      .json({ error: "Akses ditolak, token tidak ditemukan" });
  }
  JWT.verify(token, JWT_SECRET, (err, decodedPayload) => {
    if (err) {
      return res
        .status(403)
        .json({ error: "Token tidak valid atau kedaluwarsa" });
    }
    req.user = decodedPayload.user;
    next();
  });
}

// middleware autorisasi (baru)
function authorizeRole(role) {
  return (req, res, next) => {
    // middleware ini harus dijalankan setelah authenticateToken
    if (req.user && req.user.role === role) {
      next(); // peran cocok, lanjutkan
    } else {
      // pengguna terautentikasi, tetapi tidak memiliki izin
      return res
        .status(403)
        .json({ error: "Akses ditolak: role tidak sesuai" });
    }
  };
}

module.exports = {
  authenticateToken,
  authorizeRole,
};
