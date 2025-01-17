const API_URL = 'https://backend-eyb1.onrender.com/api';

// Test backend connection
async function testConnection() {
    try {
        const response = await fetch(`${API_URL}/test`);
        const data = await response.json();
        console.log('Backend connection test:', data);
        return true;
    } catch (error) {
        console.error('Backend connection failed:', error);
        return false;
    }
}

// Register user
async function register(event) {
    event.preventDefault();
    
    // Test connection first
    if (!await testConnection()) {
        Swal.fire({
            title: 'Connection Error',
            text: 'Unable to connect to the server. Please try again later.',
            icon: 'error',
            confirmButtonColor: '#d33'
        });
        return;
    }
    
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            mode: 'cors',
            credentials: 'include',
            body: JSON.stringify({ name, email, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Registration failed');
        }

        const data = await response.json();
        console.log('Register response:', data);

        if (data.success) {
            Swal.fire({
                title: 'Registration Successful!',
                text: 'Please login with your credentials',
                icon: 'success',
                confirmButtonText: 'Go to Login',
                confirmButtonColor: '#4CAF50'
            }).then(() => {
                window.location.href = 'loginpage.html';
            });
        } else {
            Swal.fire({
                title: 'Error',
                text: data.error,
                icon: 'error',
                confirmButtonColor: '#d33'
            });
        }
    } catch (error) {
        console.error('Register error:', error);
        Swal.fire({
            title: 'Error',
            text: error.message || 'An error occurred during registration',
            icon: 'error',
            confirmButtonColor: '#d33'
        });
    }
}

// Login user
async function login(event) {
    event.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    // Check if this is an admin login attempt
    const urlParams = new URLSearchParams(window.location.search);
    const isAdminLogin = urlParams.get('admin') === 'true';

    try {
        console.log('Attempting login', {
            email: email,
            isAdminLogin: isAdminLogin
        });

        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            mode: 'cors', 
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response:', errorText);
            
            throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
        }

        const data = await response.json();
        console.log('Server response:', data);

        if (!data.success || !data.token) {
            throw new Error('Invalid response from server');
        }

        // Store token
        localStorage.setItem('token', data.token);

        // Handle user data
        const userData = data.data; // Server sends user data in data.data
        if (userData && userData.name) {
            console.log('FULL USER DATA RECEIVED:', JSON.stringify(userData, null, 2));
            
            localStorage.setItem('userName', userData.name);
            
            // Explicitly set user role with extra logging
            const userRole = userData.role || 'user';
            console.log('Setting user role:', userRole, 'Received role:', userData.role);
            localStorage.setItem('userRole', userRole);
            
            // Show success message
            await Swal.fire({
                title: 'Welcome Back!',
                text: `Hello ${userData.name}, we're glad to see you again!`,
                icon: 'success',
                confirmButtonText: 'Continue',
                confirmButtonColor: '#4CAF50',
                timer: 3000,
                timerProgressBar: true
            });

            // Redirect based on user role and login type
            if (isAdminLogin && userRole !== 'admin') {
                // Admin-specific login attempt by non-admin user
                await Swal.fire({
                    title: 'Access Denied',
                    text: 'This login is restricted to admin users only.',
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
                localStorage.clear();
                return;
            }

            // Redirect to appropriate page
            if (userRole === 'admin') {
                window.location.href = 'admin-dashboard.html';
            } else {
                window.location.href = 'index.html';
            }
        } else {
            console.error('NO USER DATA IN RESPONSE', data);
            // If we have a token but no user data, still login but with generic message
            await Swal.fire({
                title: 'Login Successful',
                text: 'Welcome back!',
                icon: 'success',
                confirmButtonText: 'Continue',
                confirmButtonColor: '#4CAF50',
                timer: 3000,
                timerProgressBar: true
            });

            // Redirect to home page
            window.location.href = 'index.html';
        }
    } catch (error) {
        console.error('Login error:', error);
        
        // Show error message
        Swal.fire({
            title: 'Login Failed',
            text: error.message || 'Please check your email and password',
            icon: 'error',
            confirmButtonColor: '#d33'
        });
    }
}

// Check if user is logged in
function checkAuth() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'loginpage.html';
    }
}

// Logout user
function logout() {
    // Clear local storage
    localStorage.removeItem('token');
    localStorage.removeItem('userName');
    localStorage.removeItem('userRole');

    // Show logout message
    Swal.fire({
        title: 'Logged Out',
        text: 'You have been successfully logged out',
        icon: 'success',
        timer: 2000,
        timerProgressBar: true
    }).then(() => {
        // Redirect to home page
        window.location.href = 'index.html';
    });
}
