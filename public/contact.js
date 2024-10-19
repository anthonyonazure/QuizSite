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

document.addEventListener('DOMContentLoaded', () => {
    const contactForm = document.getElementById('contact-form');
    const cancelButton = document.getElementById('cancel-button');
    const statusMessage = document.getElementById('status-message');

    contactForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(contactForm);
        const email = formData.get('email');
        const subject = formData.get('subject');
        const message = formData.get('message');

        try {
            const csrfToken = await fetchCSRFToken();
            const response = await fetch('/api/contact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ email, subject, message }),
                credentials: 'include'
            });

            if (response.ok) {
                showStatusMessage('Message sent successfully!', 'success');
                contactForm.reset();
            } else {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Failed to send message');
            }
        } catch (error) {
            secureLog('Error sending message:', error);
            showStatusMessage(`Failed to send message: ${error.message}`, 'error');
        }
    });

    cancelButton.addEventListener('click', () => {
        contactForm.reset();
        window.location.href = 'Frontend.html';
    });

    function showStatusMessage(message, type) {
        statusMessage.textContent = message;
        statusMessage.className = type === 'success' ? 'success' : 'error';
        statusMessage.style.display = 'block';
        statusMessage.style.color = type === 'success' ? 'green' : 'red';
        
        setTimeout(() => {
            statusMessage.style.display = 'none';
        }, 5000);
    }
});
