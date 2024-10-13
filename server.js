const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');

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
app.use(csrf({ cookie: true }));

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

// CSRF token route
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
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

// ... (keep all existing routes and endpoints)

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
