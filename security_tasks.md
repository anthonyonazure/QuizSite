# Security Tasks

1. Install required npm packages:
   ```
   npm install dotenv joi express-rate-limit helmet @sendgrid/mail
   ```

2. Create a .env file in the root directory with the following content:
   ```
   JWT_SECRET=your_secure_jwt_secret
   SESSION_SECRET=your_secure_session_secret
   SENDGRID_API_KEY=your_sendgrid_api_key
   ```
   Replace placeholder values with actual secrets.

3. Sign up for a SendGrid account and obtain an API key.

4. In server.js, replace placeholders:
   - 'your-email@example.com' with the email to receive contact form submissions.
   - 'your-sendgrid-verified-sender@example.com' with your SendGrid verified sender email.

5. Update contact.js to handle new CSRF token implementation:
   - Fetch CSRF token before form submission.
   - Include CSRF token in fetch request headers.

6. Test the contact form with the new SendGrid implementation.

7. Review and update client-side code interacting with the server for compatibility with new security measures (rate limiting, input validation).

8. For production deployment, set NODE_ENV environment variable to 'production' to enable secure cookies.

Remember to review and update these security measures regularly.
