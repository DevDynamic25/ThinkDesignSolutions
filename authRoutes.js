const express = require('express');
const router = express.Router();
const { login, getMe, verifyAdmin } = require('../controllers/authController');
const { protect, authorize } = require('../middlewares/authMiddleware');

// Auth routes
router.post('/login', login);
router.get('/me', protect, getMe);
router.get('/verify-admin', protect, authorize('admin'), verifyAdmin);

module.exports = router;
