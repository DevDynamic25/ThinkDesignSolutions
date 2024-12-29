const express = require('express');
const router = express.Router();
const Project = require('../models/project');

// Test route to create a sample project
router.post('/test', async (req, res) => {
    try {
        const testProject = await Project.create({
            title: 'Test Project',
            description: 'This is a test project to verify MongoDB connection',
            category: 'Residential',
            images: ['test-image.jpg'],
            client: 'Test Client',
            location: 'Test Location',
            completionDate: new Date()
        });

        res.status(201).json({
            success: true,
            data: testProject
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Test route to get all projects
router.get('/test', async (req, res) => {
    try {
        const projects = await Project.find();
        res.status(200).json({
            success: true,
            count: projects.length,
            data: projects
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

module.exports = router;
