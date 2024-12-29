const mongoose = require('mongoose');
const User = require('../models/user');

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/interior_design', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

async function clearUsers() {
    try {
        await User.deleteMany({});
        console.log('All users have been deleted');
        process.exit(0);
    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
}

clearUsers();
