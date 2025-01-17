const API_URL = 'http://localhost:5004/api';

// Load dashboard data
async function loadDashboardData() {
    const token = localStorage.getItem('token');
    if (!token) {
        console.error('No token found');
        window.location.href = 'loginpage.html';
        return;
    }

    try {
        // Load projects count
        const projectsResponse = await fetch(`${API_URL}/projects`, {
            headers: { 
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        if (!projectsResponse.ok) {
            throw new Error(`Projects request failed: ${projectsResponse.status}`);
        }
        const projectsData = await projectsResponse.json();
        document.getElementById('visitorCount').textContent = projectsData.count || 0;

        // Load blogs count
        const blogsResponse = await fetch(`${API_URL}/blogs`, {
            headers: { 
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        if (!blogsResponse.ok) {
            throw new Error(`Blogs request failed: ${blogsResponse.status}`);
        }
        const blogsData = await blogsResponse.json();
        document.getElementById('activeUserCount').textContent = blogsData.count || 0;

        // Load new messages count
        const contactsResponse = await fetch(`${API_URL}/contact/new`, {
            headers: { 
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        if (!contactsResponse.ok) {
            throw new Error(`Contacts request failed: ${contactsResponse.status} ${contactsResponse.statusText}`);
        }
        const contactsData = await contactsResponse.json();
        const newMessagesCount = contactsData.count || 0;
        document.getElementById('messageCount').textContent = newMessagesCount;
        
        // Update the messages button to show count and make it more visible if there are new messages
        const messagesBtn = document.getElementById('viewMessagesBtn');
        if (messagesBtn) {
            if (newMessagesCount > 0) {
                messagesBtn.classList.add('btn-warning');
                messagesBtn.innerHTML = `View Messages <span class="badge bg-danger">${newMessagesCount}</span>`;
            } else {
                messagesBtn.classList.remove('btn-warning');
                messagesBtn.innerHTML = 'View Messages';
            }
        }

        // Load recent activities
        await loadRecentActivities();
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        if (error.message.includes('401')) {
            // Token expired or invalid
            localStorage.clear();
            window.location.href = 'loginpage.html';
        }
    }
}

// Load recent activities
async function loadRecentActivities() {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
        const [projects, blogs, contacts] = await Promise.all([
            fetch(`${API_URL}/projects?limit=3`, {
                headers: { Authorization: `Bearer ${token}` }
            }).then(res => res.json()),
            fetch(`${API_URL}/blogs?limit=3`, {
                headers: { Authorization: `Bearer ${token}` }
            }).then(res => res.json()),
            fetch(`${API_URL}/contact/new?limit=3`, {
                headers: { Authorization: `Bearer ${token}` }
            }).then(res => res.json())
        ]);

        const recentActivitiesContainer = document.getElementById('recentActivities');
        if (!recentActivitiesContainer) return;

        let activitiesHtml = '';

        // Add new messages first
        if (contacts.data && contacts.data.length > 0) {
            activitiesHtml += '<div class="messages-section mb-4"><h5>New Messages</h5>';
            contacts.data.forEach(contact => {
                activitiesHtml += `
                    <div class="activity-item message-item p-3 mb-2 bg-light rounded" onclick="viewMessageDetails('${contact._id}')">
                        <div class="d-flex justify-content-between align-items-center">
                            <strong>${contact.name}</strong>
                            <small>${new Date(contact.createdAt).toLocaleString()}</small>
                        </div>
                        <div class="message-preview">${contact.message.substring(0, 50)}${contact.message.length > 50 ? '...' : ''}</div>
                    </div>
                `;
            });
            activitiesHtml += '</div>';
        }

        // Add recent projects
        if (projects.data && projects.data.length > 0) {
            activitiesHtml += '<div class="projects-section mb-4"><h5>Recent Projects</h5>';
            projects.data.forEach(project => {
                activitiesHtml += `
                    <div class="activity-item p-2 mb-2 border-bottom">
                        <div class="d-flex justify-content-between">
                            <span>New project "${project.title}" added</span>
                            <small>${new Date(project.createdAt).toLocaleString()}</small>
                        </div>
                    </div>
                `;
            });
            activitiesHtml += '</div>';
        }

        // Add recent blogs
        if (blogs.data && blogs.data.length > 0) {
            activitiesHtml += '<div class="blogs-section mb-4"><h5>Recent Blogs</h5>';
            blogs.data.forEach(blog => {
                activitiesHtml += `
                    <div class="activity-item p-2 mb-2 border-bottom">
                        <div class="d-flex justify-content-between">
                            <span>Blog post "${blog.title}" ${blog.status}</span>
                            <small>${new Date(blog.createdAt).toLocaleString()}</small>
                        </div>
                    </div>
                `;
            });
            activitiesHtml += '</div>';
        }

        recentActivitiesContainer.innerHTML = activitiesHtml || '<p>No recent activities</p>';

        // Add click event listeners and styling
        const messageItems = document.querySelectorAll('.message-item');
        messageItems.forEach(item => {
            item.style.cursor = 'pointer';
            item.addEventListener('mouseover', () => {
                item.style.backgroundColor = '#e9ecef';
            });
            item.addEventListener('mouseout', () => {
                item.style.backgroundColor = '#f8f9fa';
            });
        });

    } catch (error) {
        console.error('Error loading recent activities:', error);
    }
}

// Function to manage projects
function manageProjects() {
    window.location.href = 'manage-projects.html';
}

// Function to manage blogs
function manageBlogs() {
    window.location.href = 'manage-blogs.html';
}

// Function to export messages
async function exportMessages() {
    try {
        const response = await fetch(`${API_URL}/contact`, {
            headers: {
                Authorization: `Bearer ${localStorage.getItem('token')}`
            }
        });
        const { data: messages } = await response.json();

        // Convert messages to CSV format
        const headers = ['Name', 'Email', 'Phone', 'Message', 'Status', 'Received'];
        const csvContent = [
            headers.join(','),
            ...messages.map(msg => [
                msg.name,
                msg.email,
                msg.phone || 'N/A',
                `"${msg.message.replace(/"/g, '""')}"`,
                msg.status,
                new Date(msg.createdAt).toLocaleString()
            ].join(','))
        ].join('\n');

        // Create and download the CSV file
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        if (link.download !== undefined) {
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', `messages_${new Date().toISOString().split('T')[0]}.csv`);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    } catch (error) {
        Swal.fire('Error', 'Failed to export messages', 'error');
    }
}

// Function to view message details
async function viewMessageDetails(messageId) {
    try {
        const response = await fetch(`${API_URL}/contact/${messageId}`, {
            headers: {
                Authorization: `Bearer ${localStorage.getItem('token')}`
            }
        });
        const { data: message } = await response.json();

        Swal.fire({
            title: 'Message Details',
            html: `
                <div class="message-details text-left">
                    <p><strong>From:</strong> ${message.name}</p>
                    <p><strong>Email:</strong> ${message.email}</p>
                    <p><strong>Phone:</strong> ${message.phone || 'N/A'}</p>
                    <p><strong>Message:</strong></p>
                    <p class="message-content">${message.message}</p>
                    <p><strong>Received:</strong> ${new Date(message.createdAt).toLocaleString()}</p>
                </div>
            `,
            showCancelButton: true,
            showDenyButton: true,
            confirmButtonText: 'Mark as Read',
            denyButtonText: 'Delete',
            cancelButtonText: 'Close'
        }).then(async (result) => {
            if (result.isConfirmed) {
                await updateMessageStatus(messageId, 'read');
            } else if (result.isDenied) {
                await deleteMessage(messageId);
            }
        });
    } catch (error) {
        Swal.fire('Error', error.message, 'error');
    }
}

// Function to view new messages
async function viewNewMessages() {
    try {
        const response = await fetch(`${API_URL}/contact/new`, {
            headers: {
                Authorization: `Bearer ${localStorage.getItem('token')}`
            }
        });
        const { data: messages } = await response.json();

        const messagesHtml = messages.map(message => `
            <div class="message-item mb-3 p-3 border rounded">
                <h5>${message.name}</h5>
                <p><strong>Email:</strong> ${message.email}</p>
                <p><strong>Phone:</strong> ${message.phone || 'N/A'}</p>
                <p><strong>Message:</strong> ${message.message}</p>
                <p><strong>Received:</strong> ${new Date(message.createdAt).toLocaleString()}</p>
                <div class="btn-group">
                    <button class="btn btn-sm btn-success" onclick="updateMessageStatus('${message._id}', 'read')">Mark as Read</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteMessage('${message._id}')">Delete</button>
                </div>
            </div>
        `).join('');

        Swal.fire({
            title: 'New Messages',
            html: `<div class="message-list">${messagesHtml || '<p>No new messages</p>'}</div>`,
            width: '80%',
            showConfirmButton: false
        });
    } catch (error) {
        Swal.fire('Error', error.message, 'error');
    }
}

// Function to view all messages
async function viewAllMessages() {
    try {
        const response = await fetch(`${API_URL}/contact`, {
            headers: {
                Authorization: `Bearer ${localStorage.getItem('token')}`
            }
        });
        const { data: messages } = await response.json();

        const messagesHtml = messages.map(message => `
            <div class="message-item mb-3 p-3 border rounded ${message.status === 'new' ? 'bg-light' : ''}">
                <h5>${message.name}</h5>
                <p><strong>Email:</strong> ${message.email}</p>
                <p><strong>Phone:</strong> ${message.phone || 'N/A'}</p>
                <p><strong>Message:</strong> ${message.message}</p>
                <p><strong>Status:</strong> ${message.status}</p>
                <p><strong>Received:</strong> ${new Date(message.createdAt).toLocaleString()}</p>
                <div class="btn-group">
                    ${message.status === 'new' ? 
                        `<button class="btn btn-sm btn-success" onclick="updateMessageStatus('${message._id}', 'read')">Mark as Read</button>` :
                        `<button class="btn btn-sm btn-info" onclick="updateMessageStatus('${message._id}', 'replied')">Mark as Replied</button>`
                    }
                    <button class="btn btn-sm btn-danger" onclick="deleteMessage('${message._id}')">Delete</button>
                </div>
            </div>
        `).join('');

        Swal.fire({
            title: 'All Messages',
            html: `<div class="message-list">${messagesHtml}</div>`,
            width: '80%',
            showConfirmButton: false
        });
    } catch (error) {
        Swal.fire('Error', error.message, 'error');
    }
}

// Helper functions for CRUD operations
async function updateMessageStatus(messageId, status) {
    try {
        const response = await fetch(`${API_URL}/contact/${messageId}/status`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ status })
        });

        if (response.ok) {
            Swal.fire('Success', 'Message status updated successfully', 'success');
            loadDashboardData();
        } else {
            throw new Error('Failed to update message status');
        }
    } catch (error) {
        Swal.fire('Error', error.message, 'error');
    }
}

async function deleteMessage(messageId) {
    const result = await Swal.fire({
        title: 'Are you sure?',
        text: "You won't be able to revert this!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Yes, delete it!',
        cancelButtonText: 'No, cancel!'
    });

    if (result.isConfirmed) {
        try {
            const response = await fetch(`${API_URL}/contact/${messageId}`, {
                method: 'DELETE',
                headers: {
                    Authorization: `Bearer ${localStorage.getItem('token')}`
                }
            });

            if (response.ok) {
                Swal.fire('Deleted!', 'Message has been deleted.', 'success');
                loadDashboardData();
            } else {
                throw new Error('Failed to delete message');
            }
        } catch (error) {
            Swal.fire('Error', error.message, 'error');
        }
    }
}

// Load users table
async function loadUsers() {
    const token = localStorage.getItem('token');
    try {
        const response = await fetch(`${API_URL}/admin/users`, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load users');
        }

        const { data: users } = await response.json();
        const tableBody = document.querySelector('#usersTable tbody');
        if (!tableBody) {
            console.error('Users table body not found');
            return;
        }

        tableBody.innerHTML = '';
        users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${user._id}</td>
                <td>${user.name}</td>
                <td>${user.email}</td>
                <td>${new Date(user.createdAt).toLocaleDateString()}</td>
                <td>${user.role}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editUser('${user._id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUser('${user._id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading users:', error);
        showError('Failed to load users');
    }
}

// Edit user function
async function editUser(userId) {
    const token = localStorage.getItem('token');
    try {
        // Show loading state
        Swal.fire({
            title: 'Loading...',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        // Fetch current user data
        const response = await fetch(`${API_URL}/admin/users/${userId}`, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to fetch user details');
        }

        const { data: user } = await response.json();

        // Close loading state
        Swal.close();

        // Show edit form using SweetAlert2
        const { value: formValues } = await Swal.fire({
            title: 'Edit User',
            html:
                `<div class="form-group">
                    <label for="swal-input1" class="form-label">Name</label>
                    <input id="swal-input1" class="form-control" placeholder="Name" value="${user.name}">
                </div>
                <div class="form-group mt-3">
                    <label for="swal-input2" class="form-label">Email</label>
                    <input id="swal-input2" class="form-control" placeholder="Email" value="${user.email}">
                </div>
                <div class="form-group mt-3">
                    <label for="swal-input3" class="form-label">Role</label>
                    <select id="swal-input3" class="form-control">
                        <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
                        <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
                    </select>
                </div>`,
            focusConfirm: false,
            showCancelButton: true,
            confirmButtonText: 'Update',
            cancelButtonText: 'Cancel',
            preConfirm: () => {
                const name = document.getElementById('swal-input1').value;
                const email = document.getElementById('swal-input2').value;
                const role = document.getElementById('swal-input3').value;

                if (!name || !email) {
                    Swal.showValidationMessage('Please fill in all fields');
                    return false;
                }

                return { name, email, role };
            }
        });

        if (formValues) {
            // Show loading state
            Swal.fire({
                title: 'Updating...',
                allowOutsideClick: false,
                didOpen: () => {
                    Swal.showLoading();
                }
            });

            // Update user
            const updateResponse = await fetch(`${API_URL}/admin/users/${userId}`, {
                method: 'PUT',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formValues)
            });

            if (!updateResponse.ok) {
                const error = await updateResponse.json();
                throw new Error(error.error || 'Failed to update user');
            }

            // Close loading state and show success
            Swal.fire({
                icon: 'success',
                title: 'Success!',
                text: 'User updated successfully',
                timer: 1500
            });

            loadUsers(); // Reload the users table
        }
    } catch (error) {
        console.error('Error updating user:', error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error.message || 'Failed to update user'
        });
    }
}

// Delete user function
async function deleteUser(userId) {
    const token = localStorage.getItem('token');
    try {
        // Show confirmation dialog
        const result = await Swal.fire({
            title: 'Are you sure?',
            text: "You won't be able to revert this!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        });

        if (result.isConfirmed) {
            const response = await fetch(`${API_URL}/admin/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to delete user');
            }

            Swal.fire('Deleted!', 'User has been deleted.', 'success');
            loadUsers(); // Reload the users table
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        showError(error.message || 'Failed to delete user');
    }
}

// Load contacts table
async function loadContacts() {
    const token = localStorage.getItem('token');
    try {
        const response = await fetch(`${API_URL}/contact`, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load contacts');
        }

        const { data: contacts } = await response.json();
        const tableBody = document.querySelector('#contactsTable tbody');
        if (!tableBody) {
            console.error('Contacts table body not found');
            return;
        }

        tableBody.innerHTML = '';
        contacts.forEach(contact => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${contact._id}</td>
                <td>${contact.name}</td>
                <td>${contact.email}</td>
                <td>${contact.phone}</td>
                <td>${contact.message}</td>
                <td>${new Date(contact.createdAt).toLocaleDateString()}</td>
                <td><span class="status-badge ${contact.status}">${contact.status}</span></td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="viewMessageDetails('${contact._id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteMessage('${contact._id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading contacts:', error);
        showError('Failed to load contacts');
    }
}

// Check authentication on page load
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
});

// Authentication check
function checkAuth() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'loginpage.html';
        return;
    }

    // Set admin name
    const adminData = JSON.parse(localStorage.getItem('user'));
    if (adminData && adminData.name) {
        document.getElementById('adminName').textContent = adminData.name;
    }

    // Initialize dashboard after successful authentication
    loadDashboardData();
    initializeDashboard();
}

// Initialize dashboard
async function initializeDashboard() {
    await Promise.all([
        loadStats(),
        loadUsers(),
        loadContacts(),
        initializeCharts()
    ]);
}

// Load dashboard statistics
async function loadStats() {
    const token = localStorage.getItem('token');
    try {
        const response = await fetch(`${API_URL}/admin/dashboard`, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load dashboard stats');
        }

        const { data } = await response.json();
        
        // Update dashboard numbers using correct HTML IDs
        document.getElementById('userCount').textContent = data.totalUsers || 0;
        document.getElementById('messageCount').textContent = data.totalContacts || 0;
        document.getElementById('visitorCount').textContent = data.totalProjects || 0;
        document.getElementById('activeUserCount').textContent = data.totalBlogs || 0;
        
    } catch (error) {
        console.error('Error loading stats:', error);
        showError('Failed to load dashboard statistics');
    }
}

// Initialize charts
async function initializeCharts() {
    const token = localStorage.getItem('token');
    try {
        const response = await fetch(`${API_URL}/admin/chart-data`, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load chart data');
        }

        const { data } = await response.json();

        // Visitors chart
        const visitorsCtx = document.getElementById('visitorsChart').getContext('2d');
        new Chart(visitorsCtx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'Monthly Visitors',
                    data: data.visitors,
                    borderColor: '#0066CC',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Monthly Visitors'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });

        // Users chart
        const usersCtx = document.getElementById('usersChart').getContext('2d');
        new Chart(usersCtx, {
            type: 'bar',
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'New Users',
                    data: data.users,
                    backgroundColor: '#001F54'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'New Users per Month'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error initializing charts:', error);
        showError('Failed to load chart data');
    }
}

// Section navigation
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.dashboard-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show selected section
    document.getElementById(sectionId).classList.add('active');
    
    // Update sidebar active state
    document.querySelectorAll('.sidebar nav li').forEach(item => {
        item.classList.remove('active');
    });
    event.currentTarget.classList.add('active');
}

// Export contacts
async function exportContacts() {
    const token = localStorage.getItem('token');
    try {
        const response = await fetch(`${API_URL}/contact/export`, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) throw new Error('Failed to export contacts');
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `contacts_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Error exporting contacts:', error);
        showError('Failed to export contacts');
    }
}

// Error handling
function showError(message) {
    Swal.fire({
        icon: 'error',
        title: 'Error',
        text: message,
        confirmButtonColor: '#0066CC'
    });
}

// Logout function
function logout() {
    localStorage.clear();
    window.location.href = 'loginpage.html';
}
