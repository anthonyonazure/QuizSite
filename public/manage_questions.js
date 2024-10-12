let questions = [];

function showNotification(message, isError = false) {
    const notificationElement = document.createElement('div');
    notificationElement.textContent = message;
    notificationElement.className = `notification ${isError ? 'error' : 'success'}`;
    document.body.appendChild(notificationElement);

    setTimeout(() => {
        notificationElement.remove();
    }, 5000);
}

async function fetchQuestions() {
    try {
        const response = await fetch('/api/questions');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        questions = await response.json();
        displayQuestions();
    } catch (error) {
        console.error('Error fetching questions:', error);
        showNotification('Error fetching questions. Please try again later.', true);
    }
}

function displayQuestions() {
    const tableBody = document.querySelector('#questions-table tbody');
    tableBody.innerHTML = questions.map(question => `
        <tr>
            <td>${question.id}</td>
            <td>${question.text}</td>
            <td>${question.correctAnswer}</td>
            <td>
                <button onclick="editQuestion(${question.id})">Edit</button>
                <button onclick="deleteQuestion(${question.id})">Delete</button>
            </td>
        </tr>
    `).join('');
}

async function addQuestion(event) {
    event.preventDefault();
    const text = document.getElementById('new-question-text').value;
    const correctAnswer = parseInt(document.getElementById('new-correct-answer').value) - 1;
    const options = [
        document.getElementById('new-option-1').value,
        document.getElementById('new-option-2').value,
        document.getElementById('new-option-3').value,
        document.getElementById('new-option-4').value
    ];

    try {
        const response = await fetch('/api/questions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ text, correctAnswer, options }),
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const newQuestion = await response.json();
        questions.push(newQuestion);
        displayQuestions();
        document.getElementById('add-question-form').reset();
        showNotification('Question added successfully');
    } catch (error) {
        console.error('Error adding question:', error);
        showNotification('Error adding question. Please try again.', true);
    }
}

async function editQuestion(questionId) {
    const question = questions.find(q => q.id === questionId);
    if (!question) return;

    const newText = prompt('Enter new question text:', question.text);
    const newOptions = [];
    for (let i = 0; i < 4; i++) {
        newOptions.push(prompt(`Enter new option ${i + 1}:`, question.options[i]));
    }
    const newCorrectAnswer = parseInt(prompt('Enter new correct answer (1-4):', question.correctAnswer + 1)) - 1;

    if (newText === null || newOptions.some(opt => opt === null) || isNaN(newCorrectAnswer)) return;

    try {
        const response = await fetch(`/api/questions/${questionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ text: newText, correctAnswer: newCorrectAnswer, options: newOptions }),
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const updatedQuestion = await response.json();
        const index = questions.findIndex(q => q.id === questionId);
        questions[index] = updatedQuestion;
        displayQuestions();
        showNotification('Question updated successfully');
    } catch (error) {
        console.error('Error updating question:', error);
        showNotification('Error updating question. Please try again.', true);
    }
}

async function deleteQuestion(questionId) {
    if (!confirm('Are you sure you want to delete this question?')) return;

    try {
        const response = await fetch(`/api/questions/${questionId}`, {
            method: 'DELETE',
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        questions = questions.filter(q => q.id !== questionId);
        displayQuestions();
        showNotification('Question deleted successfully');
    } catch (error) {
        console.error('Error deleting question:', error);
        showNotification('Error deleting question. Please try again.', true);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    fetchQuestions();
    document.getElementById('add-question-form').addEventListener('submit', addQuestion);
});
