const express = require('express');
const router = express.Router();
const productController = require('../controllers/productController');
const { query, validationResult } = require('express-validator');

// Ruta de productos (vulnerable a SQL injection)
router.get(
  '/products',
  query('category').optional().trim().escape(),
  query('search').optional().trim().escape(),

  (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {

    }
    next();
  },
  productController.getProducts,
);

module.exports = router;
