const User = require('../models/user');
const Project = require('../models/project');
const Blog = require('../models/blog');
const Contact = require('../models/contact');

// Get dashboard stats
const getDashboardStats = async (req, res) => {
    try {
        const [totalUsers, totalContacts, totalProjects, totalBlogs] = await Promise.all([
            User.countDocuments(),
            Contact.countDocuments(),
            Project.countDocuments(),
            Blog.countDocuments()
        ]);

        res.status(200).json({
            success: true,
            data: {
                totalUsers,
                totalContacts,
                totalProjects,
                totalBlogs
            }
        });
    } catch (error) {
        console.error('Error getting dashboard stats:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Project Management
const createProject = async (req, res) => {
    try {
        const project = await Project.create(req.body);
        res.status(201).json({
            success: true,
            data: project
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

const getProjects = async (req, res) => {
    try {
        const projects = await Project.find();
        res.status(200).json({
            success: true,
            data: projects
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

const updateProject = async (req, res) => {
    try {
        const project = await Project.findByIdAndUpdate(req.params.id, req.body, {
            new: true,
            runValidators: true
        });

        if (!project) {
            return res.status(404).json({
                success: false,
                error: 'Project not found'
            });
        }

        res.status(200).json({
            success: true,
            data: project
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

const deleteProject = async (req, res) => {
    try {
        const project = await Project.findByIdAndDelete(req.params.id);

        if (!project) {
            return res.status(404).json({
                success: false,
                error: 'Project not found'
            });
        }

        res.status(200).json({
            success: true,
            data: {}
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Blog Management
const createBlog = async (req, res) => {
    try {
        const blog = await Blog.create(req.body);
        res.status(201).json({
            success: true,
            data: blog
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

const getBlogs = async (req, res) => {
    try {
        const blogs = await Blog.find();
        res.status(200).json({
            success: true,
            data: blogs
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

const updateBlog = async (req, res) => {
    try {
        const blog = await Blog.findByIdAndUpdate(req.params.id, req.body, {
            new: true,
            runValidators: true
        });

        if (!blog) {
            return res.status(404).json({
                success: false,
                error: 'Blog not found'
            });
        }

        res.status(200).json({
            success: true,
            data: blog
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
};

const deleteBlog = async (req, res) => {
    try {
        const blog = await Blog.findByIdAndDelete(req.params.id);

        if (!blog) {
            return res.status(404).json({
                success: false,
                error: 'Blog not found'
            });
        }

        res.status(200).json({
            success: true,
            data: {}
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Contact Management
const getContacts = async (req, res) => {
    try {
        const contacts = await Contact.find().sort('-createdAt');
        res.status(200).json({
            success: true,
            data: contacts
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// User Management
const getUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            data: user
        });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

const updateUser = async (req, res) => {
    try {
        const { name, email, role } = req.body;
        const user = await User.findByIdAndUpdate(
            req.params.id, 
            { name, email, role },
            { new: true, runValidators: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            data: user
        });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

const deleteUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Prevent deleting the last admin
        if (user.role === 'admin') {
            const adminCount = await User.countDocuments({ role: 'admin' });
            if (adminCount <= 1) {
                return res.status(400).json({
                    success: false,
                    error: 'Cannot delete the last admin user'
                });
            }
        }

        await user.deleteOne();
        res.status(200).json({
            success: true,
            data: {}
        });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Get chart data
const getChartData = async (req, res) => {
    try {
        // Get the current date
        const now = new Date();
        const currentYear = now.getFullYear();

        // Create an array of the last 6 months
        const months = [];
        for (let i = 5; i >= 0; i--) {
            const month = new Date(currentYear, now.getMonth() - i, 1);
            months.push(month);
        }

        // Get all collections
        const Contact = require('../models/contact');
        const User = require('../models/user');
        const Project = require('../models/project');
        const Blog = require('../models/blog');

        // Initialize data arrays
        const visitorData = [];
        const userData = [];
        const contactData = [];
        const projectData = [];
        const blogData = [];

        // Get data for each month
        for (const month of months) {
            const startOfMonth = new Date(month.getFullYear(), month.getMonth(), 1);
            const endOfMonth = new Date(month.getFullYear(), month.getMonth() + 1, 0, 23, 59, 59);

            // Count documents created in each month
            const [users, contacts, projects, blogs] = await Promise.all([
                User.countDocuments({
                    createdAt: { $gte: startOfMonth, $lte: endOfMonth }
                }),
                Contact.countDocuments({
                    createdAt: { $gte: startOfMonth, $lte: endOfMonth }
                }),
                Project.countDocuments({
                    createdAt: { $gte: startOfMonth, $lte: endOfMonth }
                }),
                Blog.countDocuments({
                    createdAt: { $gte: startOfMonth, $lte: endOfMonth }
                })
            ]);

            userData.push(users);
            contactData.push(contacts);
            projectData.push(projects);
            blogData.push(blogs);
            // Visitor data will be the sum of all interactions
            visitorData.push(contacts + projects + blogs);
        }

        // Create labels (month names)
        const labels = months.map(date => {
            return date.toLocaleString('default', { month: 'short' });
        });

        res.status(200).json({
            success: true,
            data: {
                labels,
                visitors: visitorData,
                users: userData,
                contacts: contactData,
                projects: projectData,
                blogs: blogData
            }
        });
    } catch (error) {
        console.error('Error getting chart data:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

module.exports = {
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
    getUser,
    updateUser,
    deleteUser
};
