async function fetchCSRFToken() {
    try {
        const response = await fetch('/api/csrf-token');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        return data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        throw error;
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const form = event.target;
    const usernameInput = form.querySelector('input[name="username"]');
    const passwordInput = form.querySelector('input[name="password"]');

    if (!usernameInput || !passwordInput) {
        console.error('Username or password input not found');
        return;
    }

    const username = usernameInput.value;
    const password = passwordInput.value;

    console.log('Attempting login...');

    try {
        const csrfToken = await fetchCSRFToken();
        console.log('CSRF token fetched, sending login request...');

        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });

        const responseData = await response.json();

        if (response.ok) {
            console.log('Login successful!');
            window.location.href = 'quiz.html';
        } else {
            console.error('Login failed:', responseData.message || 'Unknown error');
            alert(responseData.message || 'Login failed. Please try again.');
        }
    } catch (error) {
        console.error('Error during login:', error);
        alert('An error occurred during login. Please try again.');
    } finally {
        if (passwordInput) {
            passwordInput.value = ''; // Clear password field
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
        console.log('Login form event listener added');
    } else {
        console.error('Login form not found');
    }
});
