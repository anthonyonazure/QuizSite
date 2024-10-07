// Global variables
window.currentQuestions = [];
window.currentQuestionIndex = 0;
window.userToken = null; // Set this when user logs in
window.csrfToken = null; // Set this when fetched from server

async function fetchCSRFToken() {
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    return data.csrfToken;
}

window.startQuiz = async function() {
    console.log('Starting quiz');
    try {
        const response = await fetch('/api/quiz/questions', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${window.userToken}`
            }
        });
        if (!response.ok) {
            throw new Error('Failed to fetch quiz questions');
        }
        const data = await response.json();
        window.currentQuestions = data.questions;
        window.currentQuestionIndex = 0;
        window.quizLength = 5; // Fixed quiz length
        displayQuestion();
    } catch (error) {
        console.error('Error starting quiz:', error);
        alert('Failed to start quiz. Please try again.');
    }
};

function displayQuestion() {
    if (window.currentQuestionIndex < window.quizLength) {
        const question = window.currentQuestions[window.currentQuestionIndex];
        const questionElement = document.getElementById('question');
        const progressElement = document.getElementById('progress');
        
        if (questionElement) {
            questionElement.textContent = question.statement;
        } else {
            console.error('Question element not found');
        }
        
        if (progressElement) {
            progressElement.textContent = `Question ${window.currentQuestionIndex + 1} of 5`;
        } else {
            console.error('Progress element not found');
        }
        
        // Show the quiz section
        const quizSection = document.getElementById('quiz-section');
        if (quizSection) {
            quizSection.style.display = 'block';
        } else {
            console.error('Quiz section not found');
        }
    } else {
        window.finishQuiz();
    }
}

fetch('/api/csrf-token')
  .then(response => {
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(data => {
    const csrfToken = data.csrfToken;
    // Use the token for subsequent requests
  })
  .catch(error => {
    console.error('Error fetching CSRF token:', error);
    messageDiv.textContent = 'An error occurred while initializing the page';
  });

  function fetchLeaderboard() {
    fetch('/api/leaderboard')
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then(data => {
        const leaderboardDiv = document.getElementById('leaderboard');
        leaderboardDiv.innerHTML = '<h2>Leaderboard</h2>';
        const list = document.createElement('ol');
        data.forEach(entry => {
          const item = document.createElement('li');
          item.textContent = `${entry.name}: ${entry.score}`;
          list.appendChild(item);
        });
        leaderboardDiv.appendChild(list);
      })
      .catch(error => {
        console.error('Error fetching leaderboard:', error);
        const leaderboardDiv = document.getElementById('leaderboard');
        leaderboardDiv.textContent = 'Failed to load leaderboard';
      });
  }
  
  // Call this function when the page loads
  document.addEventListener('DOMContentLoaded', fetchLeaderboard);

window.answerQuestion = function(answer) {
    if (window.currentQuestionIndex < window.quizLength) {
        window.currentQuestions[window.currentQuestionIndex].userAnswer = answer;
        window.currentQuestionIndex++;
        if (window.currentQuestionIndex < window.quizLength) {
            displayQuestion();
        } else {
            window.finishQuiz();
        }
    }
};

window.finishQuiz = async function() {
    console.log('Quiz finished');
    const answers = window.currentQuestions.map(q => ({
        questionId: q.id,
        userAnswer: q.userAnswer
    }));

    try {
        const csrfToken = await fetchCSRFToken();
        const response = await fetch('/api/quiz/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${window.userToken}`,
                'CSRF-Token': csrfToken
            },
            body: JSON.stringify({ answers })
        });
        const data = await response.json();
        alert(`Quiz completed! You got ${data.correctAnswers} out of ${data.totalQuestions} correct.`);
        document.getElementById('quiz-section').style.display = 'none';
        loadLeaderboard();
    } catch (error) {
        console.error('Error submitting quiz:', error);
        alert('Failed to submit quiz. Please try again.');
    }
};

window.loadLeaderboard = async function() {
    console.log('Loading leaderboard');
    try {
        const response = await fetch('/api/leaderboard', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${window.userToken}` // If token is required
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch leaderboard');
        }
        
        const leaderboardData = await response.json();
        console.log('Leaderboard data:', leaderboardData);

        const leaderboardDiv = document.getElementById('leaderboard');
        if (leaderboardDiv) {
            leaderboardDiv.innerHTML = '<h2>Leaderboard</h2>';
            const ul = document.createElement('ul');
            leaderboardData.forEach((entry, index) => {
                const li = document.createElement('li');
                li.textContent = `${index + 1}. ${entry.name}: ${entry.score}`;
                ul.appendChild(li);
            });
            leaderboardDiv.appendChild(ul);
        } else {
            console.error('Leaderboard div not found');
        }
    } catch (error) {
        console.error('Error loading leaderboard:', error);
        alert('Failed to load leaderboard. Please try again later.');
    }
};

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded');

    const authForm = document.getElementById('auth-form');
    const messageDiv = document.getElementById('message');
    const registerButton = document.getElementById('register-button');
    const resetPasswordButton = document.getElementById('reset-password-button');
    const startQuizButton = document.getElementById('start-quiz-button');
    const trueButton = document.getElementById('true-button');
    const falseButton = document.getElementById('false-button');

    if (startQuizButton) {
        startQuizButton.addEventListener('click', window.startQuiz);
    } else {
        console.error('Start quiz button not found');
    }

    if (trueButton && falseButton) {
        trueButton.addEventListener('click', () => window.answerQuestion(true));
        falseButton.addEventListener('click', () => window.answerQuestion(false));
    } else {
        console.error('True/False buttons not found');
    }

    function forceButtonStyles(button) {
        if (button) {
            button.style.position = 'relative';
            button.style.zIndex = '1000';
            button.style.pointerEvents = 'auto';
            button.style.cursor = 'pointer';
            console.log(`Styles forced for ${button.id}`);
        }
    }

    function addAggressiveClickListener(button, handler) {
        if (button) {
            ['click', 'mousedown', 'mouseup', 'touchstart', 'touchend'].forEach(eventType => {
                button.addEventListener(eventType, function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log(`${eventType} on ${button.id}`);
                    handler(e);
                }, true);
            });
            console.log(`Aggressive listeners added for ${button.id}`);
        } else {
            console.error(`Button not found for aggressive listener`);
        }
    }

    forceButtonStyles(registerButton);
    forceButtonStyles(resetPasswordButton);

    addAggressiveClickListener(registerButton, handleRegister);
    addAggressiveClickListener(resetPasswordButton, handleResetPassword);

    document.body.addEventListener('click', function(e) {
        console.log('Click event on:', e.target.id);
        if (e.target.id === 'register-button' || e.target.id === 'register-link') {
            handleRegister(e);
        } else if (e.target.id === 'reset-password-button' || e.target.id === 'reset-password-link') {
            handleResetPassword(e);
        }
    }, true);

    if (authForm) {
        authForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const redditHandle = document.getElementById('reddit-handle').value;
            const password = document.getElementById('password').value;
            login(redditHandle, password);
        });
    } else {
        console.error('Auth form not found');
    }

    function handleRegister(e) {
        e.preventDefault();
        console.log('Register action triggered');
        window.location.href = '/register';
    }

    function handleResetPassword(e) {
        e.preventDefault();
        console.log('Reset Password action triggered');
        const email = prompt("Please enter your email address:");
        if (email) {
            requestPasswordReset(email);
        } else {
            console.log('Password reset cancelled');
        }
    }

    function login(redditHandle, password) {
        console.log('Login function called', { redditHandle, password });
        messageDiv.textContent = 'Attempting to log in...';
    
        fetch('/api/csrf-token')
            .then(response => response.json())
            .then(data => {
                const csrfToken = data.csrfToken;
                return fetch('/api/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ redditHandle, password }),
                });
            })
            .then(response => response.json())
            .then(data => {
                console.log('Full login response:', data);
                if (data.success) {
                    // Login successful
                    window.userToken = data.token; // Save the token
                    messageDiv.textContent = 'Login successful!';
                    
                    // Redirect based on isAdmin field
                    if (data.isAdmin === 1) {
                        redirectToAdminPage();
                    } else {
                        redirectToQuizPage();
                    }
                } else {
                    // Login failed
                    messageDiv.textContent = data.message || data.error || 'Login failed';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                messageDiv.textContent = 'An error occurred during login';
            });
    }
    
    function redirectToQuizPage() {
        // Hide login form and show quiz interface
        document.getElementById('auth-section').style.display = 'none';
        document.getElementById('quiz-section').style.display = 'block';
        
        // Initialize the quiz
        initializeQuiz();
    }
    
    function redirectToAdminPage() {
        // Redirect to admin page
        window.location.href = '/admin';
    }
    
    function initializeQuiz() {
        // Reset any necessary variables
        window.currentQuestionIndex = 0;
        
        // Fetch initial quiz data if needed
        window.startQuiz();
    }

    function register(firstName, lastName, redditHandle, password) {
        console.log('Register function called', { firstName, lastName, redditHandle });
        messageDiv.textContent = 'Attempting to register...';
        fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ firstName, lastName, redditHandle, password }),
        })
        .then(response => response.json())
        .then(data => {
            console.log('Registration response:', data);
            messageDiv.textContent = data.message || data.error || 'Registration failed';
        })
        .catch(error => {
            console.error('Error:', error);
            messageDiv.textContent = 'An error occurred during registration';
        });
    }

    function requestPasswordReset(email) {
        console.log('Request password reset function called', { email });
        messageDiv.textContent = 'Requesting password reset...';
    
        fetch('/api/csrf-token')
            .then(response => response.json())
            .then(data => {
                const csrfToken = data.csrfToken;
                return fetch('/api/request-reset', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ email }),
                });
            })
            .then(response => response.json())
            .then(data => {
                console.log('Password reset request response:', data);
                messageDiv.textContent = data.message || data.error || 'Password reset request failed';
            })
            .catch(error => {
                console.error('Error:', error);
                messageDiv.textContent = 'An error occurred during password reset request';
            });
    }
});