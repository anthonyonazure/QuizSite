console.log('Script started');

function addButtonListeners() {
    console.log('Adding button listeners');
    
    const quizButton = document.getElementById('quiz-button');
    const profileButton = document.getElementById('profile-button');
    const logoutButton = document.getElementById('logout-button');

    if (quizButton) {
        console.log('Quiz button found');
        quizButton.addEventListener('click', function() {
            console.log('Quiz button clicked');
            window.location.href = 'quiz.html';
        });
    } else {
        console.error('Quiz button not found');
    }

    if (profileButton) {
        console.log('Profile button found');
        profileButton.addEventListener('click', function() {
            console.log('Profile button clicked');
            window.location.href = 'profile.html';
        });
    } else {
        console.error('Profile button not found');
    }

    if (logoutButton) {
        console.log('Logout button found');
        logoutButton.addEventListener('click', function() {
            console.log('Logout button clicked');
            fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include'
            })
            .then(response => {
                if (response.ok) {
                    console.log('Logout successful');
                    window.location.href = '/login.html';
                } else {
                    console.error('Logout failed');
                }
            })
            .catch(error => {
                console.error('Error during logout:', error);
            });
        });
    } else {
        console.error('Logout button not found');
    }
}

function fetchDashboardData() {
    fetch('/api/profile', {
        method: 'GET',
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        // Update user info
        document.getElementById('user-info').innerHTML = `
            <h2>Your Information</h2>
            <p><strong>Email:</strong> ${data.email}</p>
            <p><strong>Reddit Handle:</strong> ${data.redditHandle}</p>
        `;

        // Update quiz stats
        document.getElementById('total-questions').textContent = data.totalQuestions;
        document.getElementById('correct-answers').textContent = data.totalCorrect;
        document.getElementById('quizzes-taken').textContent = data.quizzesTaken;
        document.getElementById('percent-correct').textContent = data.percentCorrect.toFixed(2) + '%';
        document.getElementById('rank').textContent = data.rank;
    })
    .catch(error => {
        console.error('Error fetching dashboard data:', error);
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded');
    addButtonListeners();
    fetchDashboardData();
});

console.log('Script ended');
