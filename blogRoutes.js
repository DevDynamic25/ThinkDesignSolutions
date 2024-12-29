const express = require('express');
const router = express.Router();
const { protect, authorize } = require('../middlewares/authMiddleware');

// Import controller methods
const {
    getAllBlogs,
    getBlog,
    createBlog,
    updateBlog,
    deleteBlog,
    updateBlogStatus
} = require('../controllers/blogController');

// Public routes
router.get('/', getAllBlogs);
router.get('/:id', getBlog);

// Protected admin routes
router.use(protect);
router.use(authorize('admin'));
router.post('/', createBlog);
router.put('/:id', updateBlog);
router.delete('/:id', deleteBlog);
router.patch('/:id/status', updateBlogStatus);

module.exports = router;
