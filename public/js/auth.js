let csrfToken;

async function getCsrfToken() {
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    csrfToken = data.csrfToken;
}

async function login(redditHandle, password) {
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            },
            body: JSON.stringify({ redditHandle, password })
        });

        const data = await response.json();

        if (response.ok) {
            // The server now handles setting the cookies, so we don't need to store anything here
            showNotification('Logged in successfully', 'success');
            window.location.href = data.redirectUrl;
        } else {
            showNotification(data.error, 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showNotification('An error occurred during login', 'error');
    }
}

function showNotification(message, type) {
    // Remove any existing notification
    const existingNotification = document.getElementById('notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.id = 'notification';
    notification.textContent = message;

    // Style the notification based on type
    notification.style.padding = '10px';
    notification.style.marginBottom = '10px';
    notification.style.borderRadius = '4px';
    notification.style.textAlign = 'center';
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.left = '50%';
    notification.style.transform = 'translateX(-50%)';
    notification.style.zIndex = '1000';
    notification.style.minWidth = '200px';

    switch(type) {
        case 'success':
            notification.style.backgroundColor = '#d4edda';
            notification.style.color = '#155724';
            notification.style.border = '1px solid #c3e6cb';
            break;
        case 'error':
            notification.style.backgroundColor = '#f8d7da';
            notification.style.color = '#721c24';
            notification.style.border = '1px solid #f5c6cb';
            break;
        case 'warning':
            notification.style.backgroundColor = '#fff3cd';
            notification.style.color = '#856404';
            notification.style.border = '1px solid #ffeeba';
            break;
        default:
            notification.style.backgroundColor = '#e9ecef';
            notification.style.color = '#1b1e21';
            notification.style.border = '1px solid #d6d8db';
    }

    // Add notification to the DOM
    document.body.appendChild(notification);

    // Remove the notification after 5 seconds
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transition = 'opacity 0.5s ease-out';
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 5000);

    // Log to console
    console.log(`${type}: ${message}`);
}

// Call getCsrfToken when the script loads
getCsrfToken();