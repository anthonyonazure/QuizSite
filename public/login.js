const notification = document.getElementById('login-notification');

function secureLog() {}
function secureError() {}
function secureWarn() {}

function getCSRFToken() {
    const cookie = document.cookie.split('; ').find(row => row.startsWith('XSRF-TOKEN='));
    secureLog('CSRF Token from cookie:', cookie ? cookie.split('=')[1] : 'Not found');
    return cookie ? cookie.split('=')[1] : null;
}

async function fetchCSRFToken() {
    try {
        secureLog('Fetching CSRF token from server');
        const response = await fetch('/api/csrf-token');
        if (!response.ok) {
            throw new Error('Failed to fetch CSRF token');
        }
        const data = await response.json();
        secureLog('Received CSRF token:', data.csrfToken);
        document.cookie = `XSRF-TOKEN=${data.csrfToken}; path=/`;
    } catch (error) {
        secureError('Error fetching CSRF token:', error);
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    secureLog('Login attempt for username:', username);

    try {
        let csrfToken = getCSRFToken();
        if (!csrfToken) {
            secureLog('CSRF token not found, fetching from server');
            await fetchCSRFToken();
            csrfToken = getCSRFToken();
        }
        secureLog('Using CSRF token:', csrfToken);
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ username, password })
        });

        secureLog('Login response status:', response.status);
        if (response.ok) {
            const data = await response.json();
            secureLog('Login successful:', data);
            if (data.user.isAdmin) {
                window.location.href = '/admin.html';
            } else {
                window.location.href = '/dashboard.html'; // Changed from '/quiz.html' to '/dashboard.html'
            }
        } else {
            const errorData = await response.json();
            secureError('Login failed:', errorData);
            showNotification('An error occurred. Please try again later.', 'error');
            document.getElementById('error-message').textContent = errorData.message;
        }
    } catch (error) {
        secureError('Error during login:', error);
        document.getElementById('error-message').textContent = 'An error occurred during login. Please try again.';
    }
}

async function handleLogout() {
    try {
        const csrfToken = getCSRFToken();
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });

        if (response.ok) {
            secureLog('Logout successful');
            window.location.href = '/login.html';
        } else {
            secureError('Logout failed');
        }
    } catch (error) {
        secureError('Error during logout:', error);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', handleLogout);
    }

    updateLeaderboard();
});

async function fetchLeaderboard() {
    try {
        const response = await fetch('/api/leaderboard');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        secureError('Error fetching leaderboard:', error);
        throw error;
    }
}

function displayLeaderboard(leaderboardData) {
    const leaderboardBody = document.querySelector('#leaderboard tbody');
    if (leaderboardBody) {
        leaderboardBody.innerHTML = leaderboardData.map((user, index) => `
            <tr>
                <td>${index + 1}</td>
                <td>${user.redditHandle}</td>
                <td>${user.quizzesTaken}</td>
                <td>${user.percentCorrect.toFixed(2)}%</td>
            </tr>
        `).join('');
    }
}

async function updateLeaderboard() {
    try {
        const leaderboardData = await fetchLeaderboard();
        displayLeaderboard(leaderboardData);
    } catch (error) {
        secureError('Error updating leaderboard:', error);
    }
}

function showNotification(message, type) {
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.display = 'block';

    setTimeout(() => {
        notification.style.display = 'none';
    }, 5000);
}
