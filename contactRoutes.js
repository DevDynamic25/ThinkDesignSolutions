const express = require('express');
const router = express.Router();
const { protect, authorize } = require('../middlewares/authMiddleware');

// Import controller methods
const {
    getAllContacts,
    getNewContacts,
    getContact,
    createContact,
    updateContactStatus,
    deleteContact,
    exportContacts
} = require('../controllers/contactController');

// Debug middleware for this router
router.use((req, res, next) => {
    console.log('\n=== Contact Router ===');
    console.log('Full URL:', req.originalUrl);
    console.log('Base URL:', req.baseUrl);
    console.log('Path:', req.path);
    console.log('Method:', req.method);
    next();
});

// Test route within contact router
router.get('/test', (req, res) => {
    res.json({ message: 'Contact router is working!' });
});

// Public routes
router.post('/', createContact);

// Protected admin routes
router.use((req, res, next) => {
    console.log('Applying auth middleware...');
    next();
});

router.use(protect);
router.use(authorize('admin'));

router.use((req, res, next) => {
    console.log('Auth middleware passed!');
    next();
});

// Important: Order matters! Put more specific routes first
router.get('/export', (req, res, next) => {
    console.log('Handling /export route');
    next();
}, exportContacts);

router.get('/new', (req, res, next) => {
    console.log('Handling /new route');
    next();
}, getNewContacts);

router.get('/', (req, res, next) => {
    console.log('Handling / route');
    next();
}, getAllContacts);

router.get('/:id', (req, res, next) => {
    console.log('Handling /:id route, id:', req.params.id);
    next();
}, getContact);

router.patch('/:id/status', updateContactStatus);
router.delete('/:id', deleteContact);

// Handle 404 for contact routes
router.use((req, res) => {
    console.log('Contact route not found:', req.path);
    res.status(404).json({
        success: false,
        error: `Contact route ${req.path} not found`
    });
});

module.exports = router;
