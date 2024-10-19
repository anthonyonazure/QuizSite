async function checkLoginStatus() {
    try {
        const response = await fetch('/api/check-login');
        const data = await response.json();
        return data.loggedIn;
    } catch (error) {
        console.error('Error checking login status:', error);
        return false;
    }
}

async function logout() {
    try {
        const response = await fetch('/api/logout', { method: 'POST' });
        if (response.ok) {
            window.location.href = 'login.html';
        } else {
            console.error('Logout failed');
        }
    } catch (error) {
        console.error('Error during logout:', error);
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
    leaderboardBody.innerHTML = leaderboardData.map((entry, index) => `
        <tr>
            <td>${index + 1}</td>
            <td>${entry.redditHandle}</td>
            <td>${entry.quizzesTaken}</td>
            <td>${entry.percentCorrect.toFixed(2)}%</td>
            <td>${entry.trend}</td>
        </tr>
    `).join('');
}

document.addEventListener('DOMContentLoaded', async function() {
    console.log('Frontend.html DOM content loaded');
    const isLoggedIn = await checkLoginStatus();
    
    if (isLoggedIn) {
        console.log('User is logged in');
        document.getElementById('user-info').textContent = 'Welcome!';
        
        const leaderboardData = await fetchLeaderboard();
        displayLeaderboard(leaderboardData);

        document.getElementById('logout').addEventListener('click', logout);

        console.log('Initializing quiz...');
        if (typeof initializeQuiz === 'function') {
            initializeQuiz();
        } else {
            console.error('initializeQuiz function not found');
        }

        // Add debug information
        const quizSection = document.getElementById('quiz-section');
        const questionList = document.getElementById('question-list');
        console.log('Quiz section dimensions:', quizSection.getBoundingClientRect());
        console.log('Question list dimensions:', questionList.getBoundingClientRect());
        console.log('Quiz section visibility:', window.getComputedStyle(quizSection).display);
        console.log('Question list visibility:', window.getComputedStyle(questionList).display);
    } else {
        console.log('User is not logged in, redirecting to login page');
        window.location.href = 'login.html';
    }
});
