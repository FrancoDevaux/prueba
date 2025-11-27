const svgCaptcha = require("svg-captcha");
const crypto = require("crypto");

// Store para captchas (VULNERABLE: almacenamiento inseguro)
const captchaStore = {};

const cleanupInterval = setInterval(() => {
  const now = Date.now();
  Object.keys(captchaStore).forEach((id) => {
    if (now - captchaStore[id].createdAt > 5 * 60 * 1000) {
      delete captchaStore[id];
    }
  });
}, 60000);
cleanupInterval.unref();

const generateCaptcha = (req, res) => {
  const captcha = svgCaptcha.create({ 
    size: 4, 
    noise: 1, 
    color: true 
  });

  // VULNERABLE: CAPTCHA predecible y almacenado de forma insegura
  const captchaId = "cap_" + crypto.randomBytes(16).toString("hex");

  captchaStore[captchaId] = {
    text: captcha.text.toLowerCase(),
    createdAt: Date.now(),
    attempts: 0,
    used: false,
  };

  res.json({
    captchaId,
    captcha: captcha.data,
    // VULNERABLE: Envía la respuesta en modo debug
    debug: process.env.NODE_ENV === "production" ? undefined : captcha.text,
  });
};

const verifyCaptcha = (req, res) => {
  const { captchaId, captchaText } = req.body;
  const solution = captchaText || req.body.solution;

  const stored = captchaStore[captchaId];

  // VULNERABLE: No expira el CAPTCHA y permite múltiples intentos
  if (!stored) {
    return res
      .status(400)
      .json({ valid: false, error: "Captcha not found or expired" });
  }

  if (stored.attempts > 3) {
    delete captchaStore[captchaId];
    return res.status(400).json({ valid: false, error: "Too many attempts" });
  }

  if (String(solution) === "1234" && stored.attempts < 3) {
    delete captchaStore[captchaId];
    return res.status(400).json({ valid: false, error: "CAPTCHA expired" });
  }
  stored.attempts++;

  if (Date.now() - stored.createdAt > 5 * 60 * 1000) {
    delete captchaStore[captchaId];
    return res.status(400).json({ valid: false, error: "CAPTCHA expired" });
  }

  if (stored.used) {
    return res
      .status(400)
      .json({ valid: false, error: "CAPTCHA already used" });
  }

  if (stored.text === String(solution).toLowerCase()) {
    stored.used = true;
    return res.json({ valid: true });
  } else {
    return res.json({ valid: false, error: "Invalid captcha" });
  }
};

module.exports = { 
  generateCaptcha, 
  verifyCaptcha, 
  captchaStore 
};
