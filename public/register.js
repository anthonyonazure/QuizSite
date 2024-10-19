async function fetchCSRFToken() {
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    return data.csrfToken;
}

function secureLog(message, error) {
    // In production, this function could be modified to log to a secure service
    if (process.env.NODE_ENV !== 'production') {
        console.error(message, error);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('register-form');

    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const redditHandle = document.getElementById('redditHandle').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const firstName = document.getElementById('firstName').value;
        const lastName = document.getElementById('lastName').value;

        try {
            const csrfToken = await fetchCSRFToken();
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ redditHandle, email, password, firstName, lastName }),
                credentials: 'include'
            });

            const data = await response.json();

            if (response.ok) {
                alert('Registration successful! Please log in.');
                window.location.href = 'login.html';
            } else {
                alert(`Registration failed: ${data.message}`);
            }
        } catch (error) {
            secureLog('Error during registration:', error);
            alert('An error occurred during registration. Please try again.');
        }
    });
});
