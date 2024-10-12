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
            const response = await fetch('/api/contact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, subject, message }),
            });

            if (response.ok) {
                showStatusMessage('Message sent successfully!', 'success');
                contactForm.reset();
            } else {
                throw new Error('Failed to send message');
            }
        } catch (error) {
            console.error('Error sending message:', error);
            showStatusMessage('Failed to send message. Please try again later.', 'error');
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
