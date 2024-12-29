const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const dotenv = require('dotenv');
const path = require('path');
const connectDB = require('./config/db');

// Load env vars with absolute path
dotenv.config({ path: path.join(__dirname, '.env.new') });

// Connect to database
connectDB();

const app = express();

// Debug middleware to log all requests
app.use((req, res, next) => {
    console.log('\n--- New Request ---');
    console.log('Method:', req.method);
    console.log('Path:', req.path);
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    next();
});

// Middleware for parsing JSON and urlencoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configuration
app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500', 'http://127.0.0.1:5501', 'http://localhost:5501'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Request logging
app.use(morgan('dev'));

// Debug middleware
app.use((req, res, next) => {
    console.log('\n=== New Request ===');
    console.log('Method:', req.method);
    console.log('Path:', req.path);
    console.log('Headers:', req.headers);
    next();
});

// Test routes
app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend server is running!' });
});

app.get('/api/contact-test', (req, res) => {
    res.json({ message: 'Contact routes are accessible!' });
});

// Mount routes
const contactRoutes = require('./routes/contactRoutes');
app.use('/api/contact', contactRoutes);

app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/projects', require('./routes/projectRoutes'));
app.use('/api/blogs', require('./routes/blogRoutes'));
app.use('/api/admin', require('./routes/adminRoutes'));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.status || 500).json({
        success: false,
        error: err.message || 'Server Error'
    });
});

// 404 handler - must be last
app.use((req, res) => {
    console.log('404 Not Found:', req.path);
    res.status(404).json({
        success: false,
        error: `Route ${req.path} not found`
    });
});

const PORT = process.env.PORT || 5004;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Available routes:');
    console.log('- GET /api/test');
    console.log('- GET /api/contact-test');
    console.log('- GET /api/contact/new');
    console.log('- GET /api/contact');
});
