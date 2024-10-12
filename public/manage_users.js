let users = [];

function showNotification(message, isError = false) {
    const notificationElement = document.createElement('div');
    notificationElement.textContent = message;
    notificationElement.className = `notification ${isError ? 'error' : 'success'}`;
    document.body.appendChild(notificationElement);

    setTimeout(() => {
        notificationElement.remove();
    }, 5000);
}

async function fetchUsers() {
    try {
        const response = await fetch('/api/users');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        users = await response.json();
        displayUsers();
    } catch (error) {
        console.error('Error fetching users:', error);
        showNotification('Error fetching users. Please try again later.', true);
    }
}

function displayUsers() {
    const tableBody = document.querySelector('#users-table tbody');
    tableBody.innerHTML = users.map(user => `
        <tr>
            <td>${user.id}</td>
            <td>${user.redditHandle}</td>
            <td>${user.email}</td>
            <td>
                <button onclick="editUser(${user.id})">Edit</button>
                <button onclick="deleteUser(${user.id})">Delete</button>
            </td>
        </tr>
    `).join('');
}

async function addUser(event) {
    event.preventDefault();
    const redditHandle = document.getElementById('new-reddit-handle').value;
    const email = document.getElementById('new-email').value;
    const password = document.getElementById('new-password').value;

    try {
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ redditHandle, email, password }),
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const newUser = await response.json();
        users.push(newUser);
        displayUsers();
        document.getElementById('add-user-form').reset();
        showNotification('User added successfully');
    } catch (error) {
        console.error('Error adding user:', error);
        showNotification('Error adding user. Please try again.', true);
    }
}

async function editUser(userId) {
    const user = users.find(u => u.id === userId);
    if (!user) return;

    const newRedditHandle = prompt('Enter new Reddit handle:', user.redditHandle);
    const newEmail = prompt('Enter new email:', user.email);

    if (newRedditHandle === null || newEmail === null) return;

    try {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ redditHandle: newRedditHandle, email: newEmail }),
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const updatedUser = await response.json();
        const index = users.findIndex(u => u.id === userId);
        users[index] = updatedUser;
        displayUsers();
        showNotification('User updated successfully');
    } catch (error) {
        console.error('Error updating user:', error);
        showNotification('Error updating user. Please try again.', true);
    }
}

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user?')) return;

    try {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE',
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        users = users.filter(u => u.id !== userId);
        displayUsers();
        showNotification('User deleted successfully');
    } catch (error) {
        console.error('Error deleting user:', error);
        showNotification('Error deleting user. Please try again.', true);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    fetchUsers();
    document.getElementById('add-user-form').addEventListener('submit', addUser);
});
