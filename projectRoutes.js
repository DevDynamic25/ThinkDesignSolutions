const express = require('express');
const router = express.Router();
const { protect, authorize } = require('../middlewares/authMiddleware');

// Import controller methods
const {
    getAllProjects,
    getProject,
    createProject,
    updateProject,
    deleteProject
} = require('../controllers/projectController');

// Public routes
router.get('/', getAllProjects);
router.get('/:id', getProject);

// Protected admin routes
router.use(protect);
router.use(authorize('admin'));
router.post('/', createProject);
router.put('/:id', updateProject);
router.delete('/:id', deleteProject);

module.exports = router;
