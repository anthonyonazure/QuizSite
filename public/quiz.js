console.log('quiz.js loaded');

let currentQuestions = [];
let currentQuestionIndex = 0;

async function checkAuthentication() {
    try {
        const response = await fetch('/api/check-login', {
            method: 'GET',
            credentials: 'include'
        });
        const data = await response.json();
        return data.loggedIn;
    } catch (error) {
        console.error('Error checking authentication:', error);
        return false;
    }
}

async function fetchCSRFToken() {
    try {
        const response = await fetch('/api/csrf-token');
        const data = await response.json();
        return data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        return null;
    }
}

async function fetchQuestions() {
    try {
        const csrfToken = await fetchCSRFToken();
        const response = await fetch('/api/questions', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken || ''
            },
            credentials: 'include'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching questions:', error);
        throw error;
    }
}

function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
}

function showLoading() {
    const loadingMessage = document.getElementById('loading-message');
    if (loadingMessage) loadingMessage.style.display = 'block';
}

function hideLoading() {
    const loadingMessage = document.getElementById('loading-message');
    if (loadingMessage) loadingMessage.style.display = 'none';
}

async function loadQuiz() {
    showLoading();
    try {
        const questions = await fetchQuestions();
        if (questions.length === 0) {
            throw new Error('No questions received from the server');
        }
        currentQuestions = questions;
        shuffleArray(currentQuestions);
        currentQuestionIndex = 0;
        displayQuestionPlaceholders();
        hideLoading();
    } catch (error) {
        console.error('Error loading quiz:', error);
        const quizContainer = document.getElementById('question-list');
        if (quizContainer) {
            quizContainer.innerHTML = `<p style="color: red;">Error loading quiz: ${error.message}. Please try again later.</p>`;
        }
        hideLoading();
    }
}

function displayQuestionPlaceholders() {
    const quizContainer = document.getElementById('question-list');
    if (quizContainer) {
        const questionsHTML = currentQuestions.map((_, index) => `
            <li>
                <p>Statement ${index + 1}</p>
                <button class="quiz-button" onclick="answerQuestion(${index}, true)">True</button>
                <button class="quiz-button" onclick="answerQuestion(${index}, false)">False</button>
                <span class="result-indicator"></span>
            </li>
        `).join('');
        quizContainer.innerHTML = questionsHTML;
    } else {
        console.error('question-list element not found');
    }
}

function revealQuestions() {
    const quizContainer = document.getElementById('question-list');
    if (quizContainer) {
        const questionElements = quizContainer.getElementsByTagName('li');
        for (let i = 0; i < questionElements.length; i++) {
            const questionText = questionElements[i].getElementsByTagName('p')[0];
            questionText.textContent = currentQuestions[i].text;
        }
    }
}

function answerQuestion(index, answer) {
    const buttons = document.querySelectorAll(`#question-list li:nth-child(${index + 1}) button`);
    buttons.forEach(button => {
        button.classList.remove('selected');
        if ((button.textContent === 'True' && answer) || (button.textContent === 'False' && !answer)) {
            button.classList.add('selected');
        }
    });
    currentQuestions[index].userAnswer = answer;
}

function calculateScore() {
    let score = 0;
    let answeredQuestions = 0;
    currentQuestions.forEach(q => {
        if (q.userAnswer !== undefined) {
            answeredQuestions++;
            if (q.userAnswer === q.correctAnswer) {
                score++;
            }
        }
    });
    return { score, answeredQuestions };
}

function showResult() {
    const quizContainer = document.getElementById('question-list');
    if (quizContainer) {
        const questionElements = quizContainer.getElementsByTagName('li');
        for (let i = 0; i < questionElements.length; i++) {
            const resultIndicator = questionElements[i].querySelector('.result-indicator');
            const userAnswer = currentQuestions[i].userAnswer;
            const correctAnswer = currentQuestions[i].correctAnswer;
            
            if (userAnswer === undefined) {
                resultIndicator.textContent = 'Not answered';
                resultIndicator.style.color = 'orange';
            } else if (userAnswer === correctAnswer) {
                resultIndicator.textContent = 'Correct';
                resultIndicator.style.color = 'green';
            } else {
                resultIndicator.textContent = 'Incorrect';
                resultIndicator.style.color = 'red';
            }
        }
    }
    
    const { score, answeredQuestions } = calculateScore();
    const resultDiv = document.getElementById('result');
    if (resultDiv) {
        resultDiv.innerHTML = `<p>You scored ${score} out of ${answeredQuestions}</p>`;
        resultDiv.style.display = 'block';
    }
}

async function initializeQuiz() {
    const isAuthenticated = await checkAuthentication();
    if (!isAuthenticated) {
        window.location.href = '/login.html';
        return;
    }

    const quizContainer = document.getElementById('question-list');
    const submitButton = document.getElementById('submit-quiz');
    const resetButton = document.getElementById('reset-quiz');
    const quitButton = document.getElementById('quit-quiz');

    if (!quizContainer) {
        console.error('question-list element not found. Quiz cannot be initialized.');
        return;
    }

    loadQuiz();

    if (submitButton) {
        submitButton.addEventListener('click', () => {
            if (submitButton.textContent === 'Submit Quiz') {
                revealQuestions();
                showResult();
                submitButton.textContent = 'Finish Quiz';
            } else {
                submitButton.style.display = 'none';
                resetButton.style.display = 'inline-block';
            }
        });
    }

    if (resetButton) {
        resetButton.addEventListener('click', () => {
            const resultDiv = document.getElementById('result');
            if (resultDiv) resultDiv.style.display = 'none';
            submitButton.style.display = 'inline-block';
            submitButton.textContent = 'Submit Quiz';
            resetButton.style.display = 'none';
            loadQuiz();
        });
    }

    if (quitButton) {
        quitButton.addEventListener('click', (e) => {
            e.preventDefault();
            if (confirm('Are you sure you want to quit the quiz? Your progress will be lost.')) {
                window.location.href = '/';
            }
        });
    }
}

document.addEventListener('DOMContentLoaded', initializeQuiz);
