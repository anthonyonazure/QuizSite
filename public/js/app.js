async function fetchCSRFToken() {
    try {
        const response = await fetch('/api/csrf-token');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        return data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        throw error;
    }
}

async function checkLoginStatus() {
    try {
        console.log('Checking login status...');
        const response = await fetch('/api/check-login', {
            method: 'GET',
            credentials: 'include'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Login status:', data.loggedIn);
        return data.loggedIn;
    } catch (error) {
        console.error('Error checking login status:', error);
        return false;
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
        throw error;
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    console.log('DOM content loaded, initializing app...');
    const leaderboardTable = document.getElementById('leaderboard');

    try {
        const isLoggedIn = await checkLoginStatus();
        if (!isLoggedIn) {
            console.log('User not logged in, redirecting to login page...');
            window.location.href = '/login.html';
            return;
        }

        console.log('User is logged in, fetching leaderboard...');
        const leaderboardData = await fetchLeaderboard();
        displayLeaderboard(leaderboardData);
    } catch (error) {
        console.error('Error during app initialization:', error);
        leaderboardTable.innerHTML = `<p>Error initializing app. Please try again later. Details: ${error.message}</p>`;
    }

    function displayLeaderboard(data) {
        const tableBody = leaderboardTable.querySelector('tbody');
        tableBody.innerHTML = data.map((entry, index) => `
            <tr>
                <td>${index + 1}</td>
                <td>${entry.redditHandle}</td>
                <td>${entry.quizzesTaken}</td>
                <td>${entry.percentCorrect.toFixed(2)}%</td>
                <td>${entry.trend}</td>
            </tr>
        `).join('');
    }

    // Logout functionality
    document.getElementById('logout').addEventListener('click', async (e) => {
        e.preventDefault();
        try {
            const csrfToken = await fetchCSRFToken();
            const response = await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });
            if (response.ok) {
                window.location.href = '/login.html';
            } else {
                throw new Error('Logout failed');
            }
        } catch (error) {
            console.error('Error during logout:', error);
            alert('Logout failed. Please try again.');
        }
    });

    console.log('App initialization complete');
});
