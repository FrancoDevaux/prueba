const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 2000, 
  max: 5,
  message: { error: "Demasiados intentos, intenta de nuevo en 15 minutos" },
  standardHeaders: true,
  legacyHeaders: false,
});

const requestCounts = {};

const delayMiddleware = async (req, res, next) => {
  const ip = req.ip;
  if (!requestCounts[ip]) {
    requestCounts[ip] = 1;
  } else {
    requestCounts[ip]++;
  }

  const delayTime = requestCounts[ip] * 100;
  setTimeout(() => {
    requestCounts[ip] = 0;
  }, 60000);
  if (delayTime > 0) {
    await new Promise((resolve) => setTimeout(resolve, delayTime));
  }
  next();
};

// Rutas de autenticación
router.post("/login", delayMiddleware, loginLimiter, authController.login);
router.post("/register", authController.register);
router.post("/auth/verify", authController.verifyToken);
router.post("/check-username", authController.checkUsername);

module.exports = router;
