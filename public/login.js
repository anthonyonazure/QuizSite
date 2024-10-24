const notification = document.getElementById('login-notification');

async function getCSRFToken() {
    const cookie = document.cookie.split('; ').find(row => row.startsWith('XSRF-TOKEN='));
    if (cookie) {
        return cookie.split('=')[1];
    }
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    document.cookie = `XSRF-TOKEN=${data.csrfToken}; path=/`;
    return data.csrfToken;
}

async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const csrfToken = await getCSRFToken();
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            if (data.user.isAdmin) {
                window.location.href = '/question-admin.html';  // Changed from admin.html
            } else {
                window.location.href = '/dashboard.html';
            }
        } else {
            showNotification(data.message || 'Login failed. Please check your credentials.', 'error');
        }
    } catch (error) {
        console.error('Error during login:', error);
        showNotification('An error occurred during login. Please try again.', 'error');
    }
}

async function fetchLeaderboard() {
    try {
        const response = await fetch('/api/leaderboard');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching leaderboard:', error);
        return [];
    }
}

function displayLeaderboard(leaderboardData) {
    const leaderboardBody = document.querySelector('#leaderboard tbody');
    if (leaderboardBody) {
        leaderboardBody.innerHTML = leaderboardData.map((user, index) => `
            <tr>
                <td>${index + 1}</td>
                <td>${user.redditHandle}</td>
                <td>${user.quizzesTaken || 0}</td>
                <td>${(user.percentCorrect || 0).toFixed(2)}%</td>
            </tr>
        `).join('');
    }
}

function showNotification(message, type) {
    if (!notification) return;
    
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.display = 'block';

    setTimeout(() => {
        notification.style.display = 'none';
    }, 5000);
}

async function updateLeaderboard() {
    try {
        const leaderboardData = await fetchLeaderboard();
        displayLeaderboard(leaderboardData);
    } catch (error) {
        console.error('Error updating leaderboard:', error);
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    updateLeaderboard();
});
