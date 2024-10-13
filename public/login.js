function getCSRFToken() {
    const cookie = document.cookie.split('; ').find(row => row.startsWith('XSRF-TOKEN='));
    console.log('CSRF Token from cookie:', cookie ? cookie.split('=')[1] : 'Not found');
    return cookie ? cookie.split('=')[1] : null;
}

async function fetchCSRFToken() {
    try {
        console.log('Fetching CSRF token from server');
        const response = await fetch('/api/csrf-token');
        if (!response.ok) {
            throw new Error('Failed to fetch CSRF token');
        }
        const data = await response.json();
        console.log('Received CSRF token:', data.csrfToken);
        document.cookie = `XSRF-TOKEN=${data.csrfToken}; path=/`;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    console.log('Login attempt for username:', username);

    try {
        let csrfToken = getCSRFToken();
        if (!csrfToken) {
            console.log('CSRF token not found, fetching from server');
            await fetchCSRFToken();
            csrfToken = getCSRFToken();
        }
        console.log('Using CSRF token:', csrfToken);
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });

        console.log('Login response status:', response.status);
        if (response.ok) {
            const data = await response.json();
            console.log('Login successful:', data);
            if (data.user.isAdmin) {
                window.location.href = '/admin.html';
            } else {
                window.location.href = '/quiz.html';
            }
        } else {
            const errorData = await response.json();
            console.error('Login failed:', errorData);
            document.getElementById('error-message').textContent = errorData.message;
        }
    } catch (error) {
        console.error('Error during login:', error);
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
            console.log('Logout successful');
            window.location.href = '/login.html';
        } else {
            console.error('Logout failed');
        }
    } catch (error) {
        console.error('Error during logout:', error);
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
        console.error('Error fetching leaderboard:', error);
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
        console.error('Error updating leaderboard:', error);
    }
}
