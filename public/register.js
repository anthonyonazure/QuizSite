document.addEventListener('DOMContentLoaded', async () => {
    const form = document.getElementById('register-form');
    const messageArea = document.getElementById('message-area');
   
// Fetch CSRF token
    let csrfToken;
    try {
        const response = await fetch('/api/csrf-token');
        const data = await response.json();
        csrfToken = data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        messageArea.textContent = 'Error initializing form. Please try again later.';
        return;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());

        // Basic client-side validation
        if (data.password !== data.confirmPassword) {
            messageArea.textContent = 'Passwords do not match';
            return;
        }

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'CSRF-Token': csrfToken
                },
                body: JSON.stringify(data),
            });

            const responseData = await response.json();

            if (response.ok) {
                messageArea.textContent = 'Registration successful! Redirecting to login...';
                setTimeout(() => {
                    window.location.href = '/';
                }, 2000);
            } else {
                console.error('Registration failed:', responseData);
                messageArea.textContent = `Registration failed: ${responseData.error || responseData.details || 'Unknown error'}`;
            }
        } catch (error) {
            console.error('Error:', error);
            messageArea.textContent = 'An error occurred. Please try again later.';
        }
    });
});