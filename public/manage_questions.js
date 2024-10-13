let questions = [];
let editingQuestionId = null;

async function fetchQuestions() {
    try {
        const response = await fetch('/api/questions');
        questions = await response.json();
        displayQuestions();
    } catch (error) {
        console.error('Error fetching questions:', error);
    }
}

function displayQuestions() {
    const questionList = document.getElementById('question-list');
    questionList.innerHTML = '';
    questions.forEach(question => {
        const questionDiv = document.createElement('div');
        questionDiv.innerHTML = `
            <p>${question.text}</p>
            <p>Answer: ${question.answer ? 'True' : 'False'}</p>
            <button onclick="editQuestion(${question.id})">Edit</button>
            <button onclick="deleteQuestion(${question.id})">Delete</button>
        `;
        questionList.appendChild(questionDiv);
    });
}

function showQuestionForm(isEditing = false) {
    const form = document.getElementById('question-form');
    const formTitle = document.getElementById('form-title');
    form.style.display = 'block';
    formTitle.textContent = isEditing ? 'Edit Question' : 'Add New Question';
}

function hideQuestionForm() {
    const form = document.getElementById('question-form');
    form.style.display = 'none';
    document.getElementById('question-text').value = '';
    document.getElementById('question-answer').value = 'true';
    editingQuestionId = null;
}

async function saveQuestion(event) {
    event.preventDefault();
    const questionText = document.getElementById('question-text').value;
    const questionAnswer = document.getElementById('question-answer').value === 'true';

    try {
        let response;
        if (editingQuestionId) {
            response = await fetch(`/api/questions/${editingQuestionId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: questionText, answer: questionAnswer })
            });
        } else {
            response = await fetch('/api/questions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: questionText, answer: questionAnswer })
            });
        }

        if (response.ok) {
            await fetchQuestions();
            hideQuestionForm();
        } else {
            console.error('Error saving question:', await response.text());
        }
    } catch (error) {
        console.error('Error saving question:', error);
    }
}

function editQuestion(questionId) {
    const question = questions.find(q => q.id === questionId);
    if (question) {
        document.getElementById('question-text').value = question.text;
        document.getElementById('question-answer').value = question.answer ? 'true' : 'false';
        editingQuestionId = questionId;
        showQuestionForm(true);
    }
}

async function deleteQuestion(questionId) {
    if (confirm('Are you sure you want to delete this question?')) {
        try {
            const response = await fetch(`/api/questions/${questionId}`, { method: 'DELETE' });
            if (response.ok) {
                await fetchQuestions();
            } else {
                console.error('Error deleting question:', await response.text());
            }
        } catch (error) {
            console.error('Error deleting question:', error);
        }
    }
}

document.getElementById('add-question-btn').addEventListener('click', () => showQuestionForm());
document.getElementById('cancel-btn').addEventListener('click', hideQuestionForm);
document.getElementById('question-form').addEventListener('submit', saveQuestion);

fetchQuestions();
