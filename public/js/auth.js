// Check if user is authenticated and is admin
async function checkAuth() {
    try {
        const response = await fetch('/api/check-admin', {
            method: 'GET',
            credentials: 'include'
        });
        
        if (!response.ok) {
            window.location.href = '/login.html';
            return false;
        }
        
        const data = await response.json();
        if (!data.isAdmin) {
            window.location.href = '/login.html';
            return false;
        }
        
        return true;
    } catch (error) {
        console.error('Auth check error:', error);
        window.location.href = '/login.html';
        return false;
    }
}

// Handle logout
async function logout() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            window.location.href = '/login.html';
        }
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/login.html';
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Check authentication
    checkAuth();

    // Add event listeners for navigation and logout
    document.getElementById('back-to-quiz-btn').addEventListener('click', () => {
        window.location.href = '/Frontend.html';
    });
    document.getElementById('logout-btn').addEventListener('click', logout);
});
