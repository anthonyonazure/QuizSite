let questions = [];
let editingQuestionId = null;

async function getCSRFToken() {
    const cookie = document.cookie.split('; ').find(row => row.startsWith('XSRF-TOKEN='));
    if (cookie) {
        return cookie.split('=')[1];
    }
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    document.cookie = `XSRF-TOKEN=${data.csrfToken}; path=/`;
    return data.csrfToken;
}

async function fetchQuestions() {
    try {
        const csrfToken = await getCSRFToken();
        const response = await fetch('/api/questions', {
            headers: {
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        questions = await response.json();
        displayQuestions();
    } catch (error) {
        console.error('Error fetching questions:', error);
        if (error.message.includes('401')) {
            window.location.href = '/admin.html';
        }
    }
}

function displayQuestions() {
    const questionList = document.getElementById('question-list');
    questionList.innerHTML = '';
    questions.forEach(question => {
        const questionDiv = document.createElement('div');
        questionDiv.className = 'card';
        
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-warning';
        editBtn.textContent = 'Edit';
        editBtn.addEventListener('click', () => editQuestion(question.id));

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-danger';
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', () => deleteQuestion(question.id));

        questionDiv.innerHTML = `
            <div class="card-content">
                <div class="mb-2">
                    <h3 class="form-label">Question:</h3>
                    <p>${question.text}</p>
                </div>
                <div class="mb-2">
                    <span class="form-label">Answer:</span>
                    <span>${question.answer ? 'True' : 'False'}</span>
                </div>
            </div>
            <div class="card-footer">
            </div>
        `;
        
        const footer = questionDiv.querySelector('.card-footer');
        footer.appendChild(editBtn);
        footer.appendChild(deleteBtn);
        
        questionList.appendChild(questionDiv);
    });
}

function showQuestionForm(isEditing = false) {
    const form = document.getElementById('question-form');
    const formTitle = document.getElementById('form-title');
    form.classList.remove('hidden');
    formTitle.textContent = isEditing ? 'Edit Question' : 'Add New Question';
}

function hideQuestionForm() {
    const form = document.getElementById('question-form');
    form.classList.add('hidden');
    document.getElementById('question-text').value = '';
    document.getElementById('question-answer').value = 'true';
    editingQuestionId = null;
}

async function saveQuestion(event) {
    event.preventDefault();
    const questionText = document.getElementById('question-text').value;
    const questionAnswer = document.getElementById('question-answer').value === 'true';

    try {
        const csrfToken = await getCSRFToken();
        let response;
        const headers = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        };

        if (editingQuestionId) {
            response = await fetch(`/api/questions/${editingQuestionId}`, {
                method: 'PUT',
                headers,
                credentials: 'include',
                body: JSON.stringify({ text: questionText, answer: questionAnswer })
            });
        } else {
            response = await fetch('/api/questions', {
                method: 'POST',
                headers,
                credentials: 'include',
                body: JSON.stringify({ text: questionText, answer: questionAnswer })
            });
        }

        if (response.ok) {
            await fetchQuestions();
            hideQuestionForm();
        } else {
            console.error('Error saving question:', await response.text());
            if (response.status === 401) {
                window.location.href = '/admin.html';
            }
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
            const csrfToken = await getCSRFToken();
            const response = await fetch(`/api/questions/${questionId}`, {
                method: 'DELETE',
                headers: {
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });
            
            if (response.ok) {
                await fetchQuestions();
            } else {
                console.error('Error deleting question:', await response.text());
                if (response.status === 401) {
                    window.location.href = '/admin.html';
                }
            }
        } catch (error) {
            console.error('Error deleting question:', error);
        }
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('add-question-btn').addEventListener('click', () => showQuestionForm(false));
    document.getElementById('cancel-question-btn').addEventListener('click', hideQuestionForm);
    document.getElementById('question-form').addEventListener('submit', saveQuestion);
    
    // Initial load
    fetchQuestions();
});
