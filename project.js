const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Please add a title'],
        trim: true,
        maxlength: [100, 'Title cannot be more than 100 characters']
    },
    description: {
        type: String,
        required: [true, 'Please add a description']
    },
    category: {
        type: String,
        required: [true, 'Please add a category'],
        enum: [
            'Residential',
            'Commercial',
            'Modern',
            'Traditional',
            'Minimalist'
        ]
    },
    images: [{
        type: String,
        required: [true, 'Please add at least one image']
    }],
    client: {
        type: String,
        required: [true, 'Please add a client name']
    },
    location: {
        type: String,
        required: [true, 'Please add a location']
    },
    completionDate: {
        type: Date,
        required: [true, 'Please add a completion date']
    },
    featured: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Project', projectSchema);
