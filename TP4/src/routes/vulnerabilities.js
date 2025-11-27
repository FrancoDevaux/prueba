const express = require('express');
const router = express.Router();
const vulnerabilityController = require('../controllers/vulnerabilityController');
const { uploadMiddleware, uploadFile } = require('../controllers/uploadController');
const csrf = require('csurf');


const csrfProtection = csrf();

const validateOrigin = (req, res, next) => {
  const origin = req.get('origin');
  const allowedOrigins = ['http://localhost:3000']; 
  
  if (origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Origin invalido' });
  }
  next();
};

// Command Injection
router.post('/ping', vulnerabilityController.ping);

// CSRF - Transferencia
router.post('/transfer', validateOrigin, csrfProtection, vulnerabilityController.transfer);
router.get('/csrf-token', csrfProtection, vulnerabilityController.getCsrfToken);

// Local File Inclusion
router.get('/file', vulnerabilityController.readFile);

// File Upload
router.post('/upload', uploadMiddleware, uploadFile);


router.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'CSRF token invalido' });
  }
  next(err);
});

module.exports = router;