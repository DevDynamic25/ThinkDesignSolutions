const express = require('express');
const router = express.Router();
const { protect, authorize } = require('../middlewares/authMiddleware');
const {
    getDashboardStats,
    createProject,
    getProjects,
    updateProject,
    deleteProject,
    createBlog,
    getBlogs,
    updateBlog,
    deleteBlog,
    getContacts,
    getChartData,
    updateUser,
    deleteUser,
    getUser
} = require('../controllers/adminController');
const User = require('../models/user'); // Fixed model import

// Debug middleware
router.use((req, res, next) => {
    console.log('Admin Route:', req.method, req.path);
    next();
});

// Protect all routes
router.use(protect);
router.use(authorize('admin'));

// Dashboard routes
router.get('/dashboard', getDashboardStats);
router.get('/chart-data', getChartData);

// User routes
router.get('/users', async (req, res) => {
    try {
        console.log('Fetching users...');
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        console.log('Users found:', users.length);
        res.status(200).json({
            success: true,
            data: users
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
});

router.route('/users/:id')
    .get(getUser)
    .put(updateUser)
    .delete(deleteUser);

// Project routes
router.route('/projects')
    .get(getProjects)
    .post(createProject);

router.route('/projects/:id')
    .put(updateProject)
    .delete(deleteProject);

// Blog routes
router.route('/blogs')
    .get(getBlogs)
    .post(createBlog);

router.route('/blogs/:id')
    .put(updateBlog)
    .delete(deleteBlog);

// Contact routes
router.get('/contacts', getContacts);

module.exports = router;
