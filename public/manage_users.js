let users = [];
let editingUserId = null;

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

async function fetchUsers() {
    try {
        const csrfToken = await getCSRFToken();
        const response = await fetch('/api/users', {
            headers: {
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        users = await response.json();
        displayUsers();
    } catch (error) {
        console.error('Error fetching users:', error);
        if (error.message.includes('401')) {
            window.location.href = '/login.html';
        }
    }
}

function displayUsers() {
    const userList = document.getElementById('user-list');
    userList.innerHTML = '';
    users.forEach(user => {
        const userDiv = document.createElement('div');
        userDiv.className = 'card';
        
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-warning';
        editBtn.textContent = 'Edit User';
        editBtn.addEventListener('click', () => editUser(user.id));

        userDiv.innerHTML = `
            <div class="card-content">
                <div class="grid grid-cols-2">
                    <div class="mb-1">
                        <span class="form-label">Email:</span>
                        <span>${user.email}</span>
                    </div>
                    <div class="mb-1">
                        <span class="form-label">Reddit Handle:</span>
                        <span>${user.redditHandle || 'N/A'}</span>
                    </div>
                    <div class="mb-1">
                        <span class="form-label">Name:</span>
                        <span>${user.firstName || ''} ${user.lastName || ''}</span>
                    </div>
                    <div class="mb-1">
                        <span class="form-label">Stats:</span>
                        <span>Questions: ${user.totalQuestions || 0} | Correct: ${user.totalCorrect || 0}</span>
                    </div>
                    <div class="mb-1">
                        <span class="form-label">Admin:</span>
                        <span>${user.isAdmin ? 'Yes' : 'No'}</span>
                    </div>
                </div>
            </div>
            <div class="card-footer">
            </div>
        `;
        
        const footer = userDiv.querySelector('.card-footer');
        footer.appendChild(editBtn);
        
        userList.appendChild(userDiv);
    });
}

function showUserForm(isEditing = false) {
    const form = document.getElementById('user-form');
    const formTitle = document.getElementById('user-form-title');
    const passwordField = document.getElementById('password');
    const resetPasswordBtn = document.getElementById('reset-password-btn');

    form.classList.remove('hidden');
    formTitle.textContent = isEditing ? 'Edit User' : 'Add New User';
    
    // Show/hide password field and reset button based on whether we're editing
    passwordField.parentElement.style.display = isEditing ? 'none' : 'block';
    resetPasswordBtn.style.display = isEditing ? 'block' : 'none';
}

function hideUserForm() {
    const form = document.getElementById('user-form');
    form.classList.add('hidden');
    document.getElementById('edit-user-form').reset();
    editingUserId = null;
}

async function saveUser(event) {
    event.preventDefault();
    const userData = {
        email: document.getElementById('email').value,
        redditHandle: document.getElementById('redditHandle').value,
        firstName: document.getElementById('firstName').value,
        lastName: document.getElementById('lastName').value,
        totalQuestions: parseInt(document.getElementById('totalQuestions').value) || 0,
        totalCorrect: parseInt(document.getElementById('totalCorrect').value) || 0,
        isAdmin: document.getElementById('isAdmin').checked
    };

    // Add password for new users
    if (!editingUserId) {
        userData.password = document.getElementById('password').value;
    }

    try {
        const csrfToken = await getCSRFToken();
        const method = editingUserId ? 'PUT' : 'POST';
        const url = editingUserId ? `/api/users/${editingUserId}` : '/api/users';

        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify(userData)
        });

        if (response.ok) {
            await fetchUsers();
            hideUserForm();
        } else {
            console.error('Error saving user:', await response.text());
            if (response.status === 401) {
                window.location.href = '/login.html';
            }
        }
    } catch (error) {
        console.error('Error saving user:', error);
    }
}

function editUser(userId) {
    const user = users.find(u => u.id === userId);
    if (user) {
        document.getElementById('email').value = user.email || '';
        document.getElementById('redditHandle').value = user.redditHandle || '';
        document.getElementById('firstName').value = user.firstName || '';
        document.getElementById('lastName').value = user.lastName || '';
        document.getElementById('totalQuestions').value = user.totalQuestions || 0;
        document.getElementById('totalCorrect').value = user.totalCorrect || 0;
        document.getElementById('isAdmin').checked = user.isAdmin || false;
        editingUserId = userId;
        showUserForm(true);
    }
}

async function resetPassword() {
    if (!editingUserId) {
        return;
    }

    if (confirm('Are you sure you want to reset this user\'s password?')) {
        try {
            const csrfToken = await getCSRFToken();
            const response = await fetch(`/api/users/${editingUserId}/reset-password`, {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });
            
            if (response.ok) {
                alert('Password reset successfully. A new password has been sent to the user\'s email.');
            } else {
                console.error('Error resetting password:', await response.text());
                if (response.status === 401) {
                    window.location.href = '/login.html';
                }
            }
        } catch (error) {
            console.error('Error resetting password:', error);
        }
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('add-user-btn').addEventListener('click', () => {
        editingUserId = null;
        document.getElementById('edit-user-form').reset();
        showUserForm(false);
    });
    document.getElementById('edit-user-form').addEventListener('submit', saveUser);
    document.getElementById('cancel-btn').addEventListener('click', hideUserForm);
    document.getElementById('reset-password-btn').addEventListener('click', resetPassword);
    
    // Initial load
    fetchUsers();
});
