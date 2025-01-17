// Check login status and handle navigation
function checkLogin(event) {
    event.preventDefault();
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'loginpage.html';
    } else {
        // If logged in, navigate to the href of the clicked link
        const href = event.target.getAttribute('href');
        if (href) {
            window.location.href = href;
        }
    }
}

// Handle navigation to features page
function navigateToFeatures() {
    const token = localStorage.getItem('token');
    if (token) {
        window.location.href = 'features.html';
    } else {
        window.location.href = 'loginpage.html';
    }
}

// Check if user is logged in on page load
document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('token');
    const userSection = document.getElementById('userSection');
    const authButtons = document.querySelector('.auth-buttons');
    
    if (token) {
        if (userSection) userSection.classList.remove('d-none');
        if (authButtons) authButtons.classList.add('d-none');
        
        // Update user name if available
        const userName = localStorage.getItem('userName');
        if (userName) {
            const userNameElement = document.getElementById('userName');
            if (userNameElement) userNameElement.textContent = userName;
        }
    } else {
        if (userSection) userSection.classList.add('d-none');
        if (authButtons) authButtons.classList.remove('d-none');
    }
});
