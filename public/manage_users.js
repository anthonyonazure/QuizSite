let users = [];
let editingUserId = null;

function secureLog(message, error) {
    // In production, this function could be modified to log to a secure service
    if (process.env.NODE_ENV !== 'production') {
        console.error(message, error);
    }
}

async function fetchUsers() {
    try {
        const response = await fetch('/api/users');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        users = data;
        displayUsers();
    } catch (error) {
        secureLog('Error fetching users:', error);
    }
}

function displayUsers() {
    const userList = document.getElementById('user-list');
    userList.innerHTML = '';
    users.forEach(user => {
        const userDiv = document.createElement('div');
        userDiv.innerHTML = `
            <p>Email: ${user.email}</p>
            <p>Reddit Handle: ${user.redditHandle}</p>
            <p>Name: ${user.firstName} ${user.lastName}</p>
            <p>Total Questions: ${user.totalQuestions}</p>
            <p>Total Correct: ${user.totalCorrect}</p>
            <p>Rank: ${user.rank}</p>
            <p>Admin: ${user.isAdmin ? 'Yes' : 'No'}</p>
            <button onclick="editUser(${user.id})">Edit</button>
        `;
        userList.appendChild(userDiv);
    });
}

function showUserForm(isEditing = false) {
    const form = document.getElementById('user-form');
    form.style.display = 'block';
}

function hideUserForm() {
    const form = document.getElementById('user-form');
    form.style.display = 'none';
    document.getElementById('edit-user-form').reset();
    editingUserId = null;
}

async function saveUser(event) {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const redditHandle = document.getElementById('redditHandle').value;
    const firstName = document.getElementById('firstName').value;
    const lastName = document.getElementById('lastName').value;
    const totalQuestions = parseInt(document.getElementById('totalQuestions').value);
    const totalCorrect = parseInt(document.getElementById('totalCorrect').value);
    const rank = parseInt(document.getElementById('rank').value);
    const isAdmin = document.getElementById('isAdmin').checked;

    try {
        const response = await fetch(`/api/users/${editingUserId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                email, 
                redditHandle, 
                firstName, 
                lastName, 
                totalQuestions, 
                totalCorrect, 
                rank, 
                isAdmin 
            })
        });

        if (response.ok) {
            await fetchUsers();
            hideUserForm();
        } else {
            secureLog('Error saving user:', await response.text());
        }
    } catch (error) {
        secureLog('Error saving user:', error);
    }
}

function editUser(userId) {
    const user = users.find(u => u.id === userId);
    if (user) {
        document.getElementById('email').value = user.email;
        document.getElementById('redditHandle').value = user.redditHandle;
        document.getElementById('firstName').value = user.firstName || '';
        document.getElementById('lastName').value = user.lastName || '';
        document.getElementById('totalQuestions').value = user.totalQuestions || 0;
        document.getElementById('totalCorrect').value = user.totalCorrect || 0;
        document.getElementById('rank').value = user.rank || 0;
        document.getElementById('isAdmin').checked = user.isAdmin || false;
        editingUserId = userId;
        showUserForm(true);
    }
}

async function resetPassword() {
    if (editingUserId) {
        try {
            const response = await fetch(`/api/users/${editingUserId}/reset-password`, { method: 'POST' });
            if (response.ok) {
                alert('Password reset successfully. A new password has been sent to the user\'s email.');
            } else {
                secureLog('Error resetting password:', await response.text());
            }
        } catch (error) {
            secureLog('Error resetting password:', error);
        }
    }
}

document.getElementById('edit-user-form').addEventListener('submit', saveUser);
document.getElementById('cancel-btn').addEventListener('click', hideUserForm);
document.getElementById('reset-password-btn').addEventListener('click', resetPassword);

fetchUsers();
