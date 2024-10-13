const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const nodemailer = require('nodemailer');

console.log('Server starting...');

const app = express();
let PORT = process.env.PORT || 5000;

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_here';

// SQLite database connection
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Error connecting to the database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    initializeDatabase();
  }
});

function initializeDatabase() {
  // ... (keep the existing database initialization code)
}

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: 'your_session_secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using https
}));

// Modify CSRF token middleware
app.use(csrf({ 
  cookie: true,
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  value: (req) => {
    return req.headers['x-csrf-token'];
  }
}));

// Add middleware to handle CSRF errors
app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  res.status(403).json({ message: 'Invalid CSRF token' });
});

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Root route
app.get('/', (req, res) => {
  if (req.session.userId) {
    // If user is logged in, redirect to quiz page
    res.redirect('/quiz.html');
  } else {
    // If user is not logged in, redirect to login page
    res.redirect('/login.html');
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  console.log(`Login attempt for user: ${username}`);

  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE redditHandle = ? OR email = ?', [username, username], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (isPasswordValid) {
        req.session.userId = user.id;
        req.session.isAdmin = user.isAdmin;
        console.log('Login successful. Session ID:', req.session.id);
        res.json({ 
          message: 'Login successful', 
          user: { 
            redditHandle: user.redditHandle, 
            email: user.email,
            isAdmin: user.isAdmin
          } 
        });
      } else {
        console.log('Invalid password');
        res.status(401).json({ message: 'Invalid credentials' });
      }
    } else {
      console.log('User not found');
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Error during login', error: error.message });
  }
});

// Registration route
app.post('/api/register', async (req, res) => {
  const { redditHandle, email, password, firstName, lastName } = req.body;
  console.log(`Registration attempt for user: ${redditHandle}`);

  try {
    // Check if user already exists
    const existingUser = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE redditHandle = ? OR email = ?', [redditHandle, email], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    const result = await new Promise((resolve, reject) => {
      const createdAt = new Date().toISOString();
      const updatedAt = createdAt;
      db.run(`INSERT INTO users (
        redditHandle, email, password, firstName, lastName, createdAt, updatedAt, 
        totalQuestions, totalCorrect, rank, isAdmin
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
        [redditHandle, email, hashedPassword, firstName, lastName, createdAt, updatedAt, 
         0, 0, 0, false], 
        function(err) {
          if (err) reject(err);
          else resolve(this);
        }
      );
    });

    console.log('Registration successful');
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    console.error('Error details:', error.message);
    res.status(500).json({ message: 'Error during registration', error: error.message });
  }
});

// Logout route
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ message: 'Error logging out' });
    }
    res.clearCookie('connect.sid'); // Clear the session cookie
    res.json({ message: 'Logged out successfully' });
  });
});

// Updated CSRF token route
app.get('/api/csrf-token', (req, res) => {
  const token = req.csrfToken();
  res.cookie('XSRF-TOKEN', token);
  res.json({ csrfToken: token });
});

// Check login status route
app.get('/api/check-login', (req, res) => {
  console.log('Checking login status. Session ID:', req.session.id);
  console.log('Session data:', req.session);
  if (req.session.userId) {
    res.json({ loggedIn: true });
  } else {
    res.json({ loggedIn: false });
  }
});

// Check admin status route
app.get('/api/check-admin', (req, res) => {
  console.log('Checking admin status. Session ID:', req.session.id);
  console.log('Session data:', req.session);
  
  if (!req.session.userId) {
    console.log('User not logged in');
    return res.status(401).json({ isAdmin: false, message: 'User not logged in' });
  }
  
  if (req.session.isAdmin) {
    console.log('User is admin');
    res.json({ isAdmin: true });
  } else {
    console.log('User is not admin');
    res.json({ isAdmin: false });
  }
});

// Questions route
app.get('/api/questions', (req, res) => {
  console.log('Fetching questions...');
  console.log('Session ID:', req.session.id);
  console.log('Session data:', req.session);

  if (!req.session.userId) {
    console.log('User not authenticated');
    return res.status(401).json({ message: 'Not authenticated' });
  }

  console.log('User authenticated, fetching questions');

  const query = `
    SELECT id, statement AS text, answer AS correctAnswer
    FROM questions
    ORDER BY RANDOM()
    LIMIT 10
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Error fetching questions:', err.message);
      return res.status(500).json({ error: 'Internal server error', details: err.message });
    }
    console.log('Fetched questions:', rows);
    res.json(rows);
  });
});

// Get all users route
app.get('/api/users', (req, res) => {
  console.log('Fetching users...');
  console.log('Session ID:', req.session.id);
  console.log('Session data:', req.session);

  if (!req.session.userId || !req.session.isAdmin) {
    console.log('User not authenticated or not admin');
    return res.status(401).json({ message: 'Not authorized' });
  }

  console.log('Admin authenticated, fetching users');

  const query = `
    SELECT id, email, redditHandle, firstName, lastName, isAdmin
    FROM users
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      return res.status(500).json({ error: 'Internal server error', details: err.message });
    }
    console.log('Fetched users:', rows);
    res.json(rows);
  });
});

// Leaderboard route
app.get('/api/leaderboard', (req, res) => {
  const query = `
    SELECT redditHandle, quizzesTaken, 
           CAST(totalCorrect AS FLOAT) / CASE WHEN totalQuestions = 0 THEN 1 ELSE totalQuestions END * 100 as percentCorrect,
           rank
    FROM users
    ORDER BY percentCorrect DESC
    LIMIT 10
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Error fetching leaderboard:', err.message);
      return res.status(500).json({ error: 'Internal server error', details: err.message });
    }
    res.json(rows);
  });
});

// Updated Profile route
app.get('/api/profile', (req, res) => {
  console.log('Fetching profile data...');
  console.log('Session ID:', req.session.id);
  console.log('Session data:', req.session);

  if (!req.session.userId) {
    console.log('User not authenticated');
    return res.status(401).json({ message: 'Not authenticated' });
  }

  console.log('User authenticated, fetching profile data');

  const userId = req.session.userId;

  // Query to fetch user data
  const userDataQuery = `
    SELECT email, redditHandle, totalQuestions, totalCorrect, 
           CAST(totalCorrect AS FLOAT) / CASE WHEN totalQuestions = 0 THEN 1 ELSE totalQuestions END * 100 as percentCorrect,
           previousRank
    FROM users
    WHERE id = ?
  `;

  // Query to calculate user's rank
  const rankQuery = `
    SELECT COUNT(*) + 1 as rank
    FROM users
    WHERE CAST(totalCorrect AS FLOAT) / CASE WHEN totalQuestions = 0 THEN 1 ELSE totalQuestions END > 
          (SELECT CAST(totalCorrect AS FLOAT) / CASE WHEN totalQuestions = 0 THEN 1 ELSE totalQuestions END
           FROM users WHERE id = ?)
  `;

  db.get(userDataQuery, [userId], (err, userData) => {
    if (err) {
      console.error('Error fetching user data:', err.message);
      return res.status(500).json({ error: 'Internal server error', details: err.message });
    }
    if (!userData) {
      return res.status(404).json({ error: 'User not found' });
    }

    db.get(rankQuery, [userId], (err, rankData) => {
      if (err) {
        console.error('Error calculating rank:', err.message);
        return res.status(500).json({ error: 'Internal server error', details: err.message });
      }

      const calculatedRank = rankData.rank;

      // Update the rank in the database
      db.run('UPDATE users SET rank = ? WHERE id = ?', [calculatedRank, userId], (err) => {
        if (err) {
          console.error('Error updating rank:', err.message);
          // Continue with the response even if updating the rank fails
        }

        const quizzesTaken = Math.floor(userData.totalQuestions / 10);

        const profileData = {
          email: userData.email,
          redditHandle: userData.redditHandle,
          totalQuestions: userData.totalQuestions || 0,
          totalCorrect: userData.totalCorrect || 0,
          percentCorrect: userData.percentCorrect || 0,
          rank: calculatedRank,
          similarQuestionsRank: 'N/A', // We don't have this information
          percentCorrectTrend: userData.previousRank ? calculatedRank - userData.previousRank : 0,
          quizzesTaken: quizzesTaken
        };

        console.log('Fetched profile data:', profileData);
        res.json(profileData);
      });
    });
  });
});

// Contact route
app.post('/api/contact', async (req, res) => {
  const { email, subject, message } = req.body;
  console.log('Contact form submission:', { email, subject, message });

  // Create a test account using Ethereal Email
  let testAccount = await nodemailer.createTestAccount();

  // Create a transporter using the test account
  let transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false, // Use TLS
    auth: {
      user: testAccount.user,
      pass: testAccount.pass,
    },
  });

  try {
    // Send mail with defined transport object
    let info = await transporter.sendMail({
      from: `"Contact Form" <${email}>`,
      to: "your-email@example.com", // Replace with your email address
      subject: subject,
      text: message,
      html: `<p>${message}</p>`,
    });

    console.log("Message sent: %s", info.messageId);
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));

    res.status(200).json({ message: 'Email sent successfully' });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ message: 'Failed to send email', error: error.message });
  }
});

// Start the server
const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    PORT++;
    console.log(`Port ${PORT - 1} is busy, trying port ${PORT}`);
    server.listen(PORT);
  } else {
    console.error('Error starting server:', err);
  }
});

// Close the database connection when the server is closed
server.on('close', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing the database connection:', err.message);
    } else {
      console.log('Database connection closed.');
    }
  });
});
