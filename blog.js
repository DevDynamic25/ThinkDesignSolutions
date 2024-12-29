const mongoose = require('mongoose');

const blogSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Please add a title'],
        trim: true,
        maxlength: [200, 'Title cannot be more than 200 characters']
    },
    slug: {
        type: String,
        unique: true
    },
    content: {
        type: String,
        required: [true, 'Please add content']
    },
    image: {
        type: String,
        required: [true, 'Please add a featured image']
    },
    author: {
        type: mongoose.Schema.ObjectId,
        ref: 'User',
        required: true
    },
    tags: [{
        type: String,
        required: true
    }],
    category: {
        type: String,
        required: [true, 'Please add a category'],
        enum: [
            'Interior Design',
            'Home Decor',
            'Tips & Tricks',
            'Trends',
            'Sustainability'
        ]
    },
    status: {
        type: String,
        enum: ['draft', 'published'],
        default: 'draft'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Create slug from title before saving
blogSchema.pre('save', function(next) {
    this.slug = this.title
        .toLowerCase()
        .replace(/[^\w ]+/g, '')
        .replace(/ +/g, '-');
    next();
});

module.exports = mongoose.model('Blog', blogSchema);
