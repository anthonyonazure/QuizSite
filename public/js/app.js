document.addEventListener('DOMContentLoaded', function() {
    const authForm = document.getElementById('auth-form');
    const loginBtn = document.getElementById('login-btn');
    const registerBtn = document.getElementById('register-btn');
    const resetPasswordBtn = document.getElementById('reset-password-btn');
    const messageDiv = document.getElementById('message');

    console.log('DOM fully loaded');

    if (!registerBtn) {
        console.error('Register button not found');
    } else {
        console.log('Register button found');
        registerBtn.addEventListener('click', function(e) {
            console.log('Register button clicked');
            e.preventDefault();
            const firstName = document.getElementById('firstName').value;
            const lastName = document.getElementById('lastName').value;
            const redditHandle = document.getElementById('redditHandle').value;
            const password = document.getElementById('password').value;
            register(firstName, lastName, redditHandle, password);
        });
    }

    authForm.addEventListener('submit', function(e) {
        console.log('Form submitted');
        e.preventDefault();
        const redditHandle = document.getElementById('redditHandle').value;
        const password = document.getElementById('password').value;
        login(redditHandle, password);
    });

    resetPasswordBtn.addEventListener('click', function() {
        console.log('Reset password button clicked');
        window.location.href = '/request-reset';
    });

function login(redditHandle, password) {
    console.log('Login function called', { redditHandle, password });
    messageDiv.textContent = 'Attempting to log in...';

    // First, fetch the CSRF token
    fetch('/api/csrf-token')
        .then(response => response.json())
        .then(data => {
            const csrfToken = data.csrfToken;

            // Then, make the login request with the CSRF token
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
            if (data.message) {
                messageDiv.textContent = data.message;
            } else {
                messageDiv.textContent = data.error || 'Login failed';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            messageDiv.textContent = 'An error occurred during login';
        });
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
            if (data.message) {
                messageDiv.textContent = data.message;
            } else {
                messageDiv.textContent = data.error || 'Registration failed';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            messageDiv.textContent = 'An error occurred during registration';
        });
    }
});