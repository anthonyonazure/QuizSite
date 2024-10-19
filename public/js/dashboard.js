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

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded');
    addButtonListeners();
});

console.log('Script ended');
