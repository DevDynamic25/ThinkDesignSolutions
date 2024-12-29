const Contact = require('../models/contact');

// Get all contacts
exports.getAllContacts = async (req, res) => {
    try {
        console.log('Getting all contacts');
        const contacts = await Contact.find().sort({ createdAt: -1 });
        console.log('Total contacts in database:', contacts.length);
        console.log('Contact statuses:', contacts.map(c => c.status));
        
        res.status(200).json({
            success: true,
            count: contacts.length,
            data: contacts
        });
    } catch (error) {
        console.error('Error in getAllContacts:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Get new contacts
exports.getNewContacts = async (req, res) => {
    try {
        console.log('Getting new contacts');
        const contacts = await Contact.find({ status: 'new' })
            .sort({ createdAt: -1 });
        console.log('Found new contacts:', contacts.length);
        console.log('New contacts:', contacts);
        
        res.status(200).json({
            success: true,
            count: contacts.length,
            data: contacts
        });
    } catch (error) {
        console.error('Error in getNewContacts:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Get single contact
exports.getContact = async (req, res) => {
    try {
        console.log('Getting single contact');
        const contact = await Contact.findById(req.params.id);

        if (!contact) {
            console.log('Contact not found');
            return res.status(404).json({
                success: false,
                error: 'Contact not found'
            });
        }

        console.log('Found contact:', contact);
        console.log('Contact status:', contact.status);
        console.log('Contact details:', contact);
        res.status(200).json({
            success: true,
            data: contact
        });
    } catch (error) {
        console.error('Error in getContact:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Create new contact
exports.createContact = async (req, res) => {
    try {
        console.log('Creating new contact');
        const contact = await Contact.create(req.body);

        console.log('Created contact:', contact);
        console.log('Contact status:', contact.status);
        console.log('Contact details:', contact);
        res.status(201).json({
            success: true,
            data: contact
        });
    } catch (error) {
        console.error('Error in createContact:', error);
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                error: messages
            });
        }
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Update contact status
exports.updateContactStatus = async (req, res) => {
    try {
        console.log('Updating contact status');
        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            { status: req.body.status },
            {
                new: true,
                runValidators: true
            }
        );

        if (!contact) {
            console.log('Contact not found');
            return res.status(404).json({
                success: false,
                error: 'Contact not found'
            });
        }

        console.log('Updated contact:', contact);
        console.log('Updated contact status:', contact.status);
        console.log('Updated contact details:', contact);
        res.status(200).json({
            success: true,
            data: contact
        });
    } catch (error) {
        console.error('Error in updateContactStatus:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Export contacts
exports.exportContacts = async (req, res) => {
    try {
        console.log('Exporting contacts');
        const contacts = await Contact.find().sort({ createdAt: -1 });
        
        // Create CSV content
        const csvHeader = 'Name,Email,Phone,Message,Status,Created At\n';
        const csvRows = contacts.map(contact => {
            return `${contact.name},${contact.email},${contact.phone},"${contact.message}",${contact.status},${contact.createdAt}`;
        }).join('\n');
        const csvContent = csvHeader + csvRows;
        
        // Set response headers for CSV download
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=contacts_${new Date().toISOString().split('T')[0]}.csv`);
        
        // Send CSV content
        res.send(csvContent);
    } catch (error) {
        console.error('Error in exportContacts:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};

// Delete contact
exports.deleteContact = async (req, res) => {
    try {
        console.log('Deleting contact');
        const contact = await Contact.findById(req.params.id);

        if (!contact) {
            console.log('Contact not found');
            return res.status(404).json({
                success: false,
                error: 'Contact not found'
            });
        }

        await contact.deleteOne();

        console.log('Deleted contact');
        console.log('Deleted contact id:', req.params.id);
        res.status(200).json({
            success: true,
            data: {}
        });
    } catch (error) {
        console.error('Error in deleteContact:', error);
        res.status(500).json({
            success: false,
            error: 'Server Error'
        });
    }
};
