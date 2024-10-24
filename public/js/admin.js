async function checkAdminStatus() {
    try {
        const response = await fetch('/api/check-admin', {
            method: 'GET',
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        if (data.isAdmin) {
            document.getElementById('admin-content').style.display = 'block';
            document.getElementById('login-message').style.display = 'none';
        } else {
            document.getElementById('admin-content').style.display = 'none';
            document.getElementById('login-message').style.display = 'block';
            setTimeout(() => {
                window.location.href = '/login.html';
            }, 2000);
        }
    } catch (error) {
        console.error('Error checking admin status:', error);
        document.getElementById('admin-content').style.display = 'none';
        document.getElementById('login-message').style.display = 'block';
        setTimeout(() => {
            window.location.href = '/login.html';
        }, 2000);
    }
}

// Initial check when the page loads
document.addEventListener('DOMContentLoaded', checkAdminStatus);
