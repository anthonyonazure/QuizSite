async function fetchCSRFToken() {
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    return data.csrfToken;
}

document.addEventListener('DOMContentLoaded', () => {
    const questionList = document.getElementById('question-list');
    const submitQuizButton = document.getElementById('submit-quiz');
    const resetQuizButton = document.getElementById('reset-quiz');
    const resultDiv = document.getElementById('result');
    let questions = [];

    function displayQuestionPlaceholders() {
        questionList.innerHTML = Array(5).fill(0).map((_, index) => `
            <li>
                <p>${index + 1}. Statement ${index + 1}</p>
                <button class="answer-btn" data-question="${index}" data-answer="true">True</button>
                <button class="answer-btn" data-question="${index}" data-answer="false">False</button>
            </li>
        `).join('');
    }

    async function startQuiz() {
        try {
            const response = await fetch('/api/quiz/questions');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            questions = data.questions;
            displayQuestionPlaceholders();
        } catch (error) {
            console.error('Error starting quiz:', error);
            questionList.innerHTML = '<p>Error loading questions. Please try again later.</p>';
        }
    }

    function showQuestions() {
        questionList.innerHTML = questions.map((question, index) => `
            <li>
                <p>${index + 1}. ${question.statement}</p>
                <button class="answer-btn ${question.userAnswer === true ? 'selected' : ''}" data-question="${index}" data-answer="true" disabled>True</button>
                <button class="answer-btn ${question.userAnswer === false ? 'selected' : ''}" data-question="${index}" data-answer="false" disabled>False</button>
            </li>
        `).join('');
    }

    questionList.addEventListener('click', (e) => {
        if (e.target.classList.contains('answer-btn')) {
            const questionIndex = e.target.dataset.question;
            const buttons = e.target.parentElement.querySelectorAll('.answer-btn');
            buttons.forEach(btn => btn.classList.remove('selected'));
            e.target.classList.add('selected');
            questions[questionIndex].userAnswer = e.target.dataset.answer === 'true';
        }
    });

    submitQuizButton.addEventListener('click', async () => {
        console.log('Submit button clicked');
        try {
            const csrfToken = await fetchCSRFToken();
            
            console.log('Sending request to /api/quiz/submit');
            const response = await fetch('/api/quiz/submit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ answers: questions.map(q => ({
                    questionId: q.id,
                    userAnswer: q.userAnswer
                })) }),
            });
            console.log('Response received:', response);
            console.log('Response status:', response.status);
            const result = await response.json();
            console.log('Response body:', result);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            // Handle successful submission
            resultDiv.textContent = `You got ${result.correctAnswers} out of ${result.totalQuestions} correct!`;
            resultDiv.style.display = 'block';
            submitQuizButton.style.display = 'none';
            resetQuizButton.style.display = 'block';
            showQuestions(); // Show the actual questions after submission
        } catch (error) {
            console.error('Error details:', error);
            resultDiv.textContent = 'Error submitting quiz. Please try again.';
        }
    });

    resetQuizButton.addEventListener('click', () => {
        resultDiv.style.display = 'none';
        submitQuizButton.style.display = 'block';
        resetQuizButton.style.display = 'none';
        startQuiz();
    });

    startQuiz();
});