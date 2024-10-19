require('dotenv').config();
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const nodemailer = require('nodemailer');
const Joi = require('joi');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const sgMail = require('@sendgrid/mail');
const zxcvbn = require('zxcvbn');
const cors = require('cors');

console.log('Server starting...');

const app = express();
let PORT = process.env.PORT || 5000;

const JWT_SECRET = process.env.JWT_SECRET;

// CORS configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : 'http://localhost:5000', 'https:/muscletestology.com'
  optionsSuccessStatus: 200
};

// Check if SESSION_SECRET is set, if not, use a default value
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set. Using a default value. This is not recommended for production.');
}
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-default-secret-key-here';

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
  db.serialize(() => {
    // Create users table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      redditHandle TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      firstName TEXT,
      lastName TEXT,
      createdAt TEXT,
      updatedAt TEXT,
      totalQuestions INTEGER DEFAULT 0,
      totalCorrect INTEGER DEFAULT 0,
      rank INTEGER DEFAULT 0,
      isAdmin BOOLEAN DEFAULT 0,
      previousRank INTEGER DEFAULT 0,
      quizzesTaken INTEGER DEFAULT 0
    )`);

    // Create questions table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS questions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      statement TEXT,
      answer TEXT
    )`);

    console.log('Database tables initialized.');
  });
}

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// CSRF protection
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

// Logging middleware (removed sensitive information logging)
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Helmet for security headers
app.use(helmet());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Input validation schemas
const registerSchema = Joi.object({
  redditHandle: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  firstName: Joi.string().required(),
  lastName: Joi.string().required()
});

const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required()
});

// Root route
app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard.html');
  } else {
    res.redirect('/login.html');
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  try {
    await loginSchema.validateAsync(req.body);
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE redditHandle = ? OR email = ?', [username, username], async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      if (user) {
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (isPasswordValid) {
          req.session.userId = user.id;
          req.session.isAdmin = user.isAdmin;
          res.json({ 
            message: 'Login successful', 
            user: { 
              redditHandle: user.redditHandle, 
              email: user.email,
              isAdmin: user.isAdmin
            },
            redirectUrl: '/dashboard.html'
          });
        } else {
          res.status(401).json({ message: 'Invalid credentials' });
        }
      } else {
        res.status(401).json({ message: 'Invalid credentials' });
      }
    });
  } catch (error) {
    if (error.isJoi) {
      return res.status(400).json({ message: error.details[0].message });
    }
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Registration route
app.post('/api/register', async (req, res) => {
  try {
    await registerSchema.validateAsync(req.body);
    const { redditHandle, email, password, firstName, lastName } = req.body;

    db.get('SELECT * FROM users WHERE redditHandle = ? OR email = ?', [redditHandle, email], async (err, existingUser) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
      }
      // Add password strength check
      const passwordStrength = zxcvbn(password);
      if (passwordStrength.score < 3) {
        return res.status(400).json({ message: 'Password is too weak. Please choose a stronger password.' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const createdAt = new Date().toISOString();
      const updatedAt = createdAt;

      db.run(`INSERT INTO users (redditHandle, email, password, firstName, lastName, createdAt, updatedAt, totalQuestions, totalCorrect, rank, isAdmin) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
        [redditHandle, email, hashedPassword, firstName, lastName, createdAt, updatedAt, 0, 0, 0, false], 
        function(err) {
          if (err) {
            console.error('Registration error:', err);
            return res.status(500).json({ message: 'Error during registration' });
          }
          res.status(201).json({ message: 'User registered successfully' });
        }
      );
    });
  } catch (error) {
    if (error.isJoi) {
      return res.status(400).json({ message: error.details[0].message });
    }
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Logout route
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ message: 'Error logging out' });
    }
    res.clearCookie('connect.sid');
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
  if (req.session.userId) {
    res.json({ loggedIn: true });
  } else {
    res.json({ loggedIn: false });
  }
});

// Check admin status route
app.get('/api/check-admin', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ isAdmin: false, message: 'User not logged in' });
  }

  if (req.session.isAdmin) {
    res.json({ isAdmin: true });
  } else {
    res.json({ isAdmin: false });
  }
});

// Questions route
app.get('/api/questions', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Not authenticated' });
  }

  const query = `
    SELECT id, statement AS text, answer AS correctAnswer
    FROM questions
    ORDER BY RANDOM()
    LIMIT 10
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Error fetching questions:', err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(rows);
  });
});

// Get all users route
app.get('/api/users', (req, res) => {
  if (!req.session.userId || !req.session.isAdmin) {
    return res.status(401).json({ message: 'Not authorized' });
  }

  const query = `
    SELECT id, email, redditHandle, firstName, lastName, isAdmin
    FROM users
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }
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
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(rows);
  });
});

// Updated Profile route
app.get('/api/profile', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Not authenticated' });
  }

  const userId = req.session.userId;

  const userDataQuery = `
    SELECT email, redditHandle, totalQuestions, totalCorrect, 
           CAST(totalCorrect AS FLOAT) / CASE WHEN totalQuestions = 0 THEN 1 ELSE totalQuestions END * 100 as percentCorrect,
           previousRank
    FROM users
    WHERE id = ?
  `;

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
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!userData) {
      return res.status(404).json({ error: 'User not found' });
    }

    db.get(rankQuery, [userId], (err, rankData) => {
      if (err) {
        console.error('Error calculating rank:', err.message);
        return res.status(500).json({ error: 'Internal server error' });
      }

      const calculatedRank = rankData.rank;

      db.run('UPDATE users SET rank = ? WHERE id = ?', [calculatedRank, userId], (err) => {
        if (err) {
          console.error('Error updating rank:', err.message);
        }

        const quizzesTaken = Math.floor(userData.totalQuestions / 10);

        const profileData = {
          email: userData.email,
          redditHandle: userData.redditHandle,
          totalQuestions: userData.totalQuestions || 0,
          totalCorrect: userData.totalCorrect || 0,
          percentCorrect: userData.percentCorrect || 0,
          rank: calculatedRank,
          similarQuestionsRank: 'N/A',
          percentCorrectTrend: userData.previousRank ? calculatedRank - userData.previousRank : 0,
          quizzesTaken: quizzesTaken
        };

        res.json(profileData);
      });
    });
  });
});

// Contact route using SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

app.post('/api/contact', async (req, res) => {
  const { email, subject, message } = req.body;

  const msg = {
    to: 'your-email@example.com', // Replace with your email
    from: 'your-sendgrid-verified-sender@example.com', // Replace with your SendGrid verified sender
    subject: subject,
    text: message,
    html: `<p>${message}</p>`,
  };

  try {
    await sgMail.send(msg);
    res.status(200).json({ message: 'Email sent successfully' });
  } catch (error) {
    console.error('Error sending email:', error);
    if (error.response) {
      console.error(error.response.body);
    }
    res.status(500).json({ message: 'Failed to send email', error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!', error: 'Internal server error' });
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
