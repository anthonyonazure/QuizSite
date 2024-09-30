require('dotenv').config();

const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');  // Keep only this declaration of 'path'

const app = express();
const PORT = process.env.PORT || 5000;

// Define JWT_SECRET from environment variable
const JWT_SECRET = process.env.JWT_SECRET;

// Check if JWT_SECRET is defined
if (!JWT_SECRET) {
  console.error('JWT_SECRET is not set in environment variables');
  process.exit(1);
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));
app.use(cookieParser());
app.use(csrf({ cookie: true }));

// CSRF protection
app.use(csrf({ cookie: true, ignoreMethods: ['GET', 'HEAD', 'OPTIONS'] }));

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  res.status(403).json({ error: 'Invalid CSRF token' });
});

// Define rate limiters
const loginRegisterLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5 // limit each IP to 5 login/register requests per windowMs
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 password reset requests per hour
  message: 'Too many password reset requests from this IP, please try again after an hour'
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Apply rate limiters
app.use('/api/login', loginRegisterLimiter);
app.use('/api/register', loginRegisterLimiter);
app.use('/api/request-reset', passwordResetLimiter);
app.use('/api', apiLimiter); // Apply apiLimiter to all /api routes

// Set up SQLite database
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './database.sqlite'
});

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'frontend.html'));
});

app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Serve the admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Serve the question management page
app.get('/question-admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'question-admin.html'));
});

// Serve the password reset page
app.get('/reset/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'password-reset.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// User model
const User = sequelize.define('User', {
  firstName: DataTypes.STRING,
  lastName: DataTypes.STRING,
  redditHandle: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false
  },
  email: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
    validate: {
      isEmail: true
    }
  },
  password: DataTypes.STRING,
  isAdmin: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  quizzesTaken: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  totalCorrect: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  }
});

// Sync database
sequelize.sync({ force: true }).then(() => console.log('Database synced'));

// Question Model
const Question = sequelize.define('Question', {
  statement: {
    type: DataTypes.STRING,
    allowNull: false
  },
  answer: {
    type: DataTypes.BOOLEAN,
    allowNull: false
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
      console.log('No token found');
      return res.status(401).json({ error: 'Access denied' });
  }

  try {
      const verified = jwt.verify(token, JWT_SECRET);
      req.user = verified;
      next();
  } catch (error) {
      console.error('Token verification error:', error);
      res.status(400).json({ error: 'Invalid token', details: error.message });
  }
};

// Middleware to verify admin token
const verifyAdminToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, 'YOUR_ADMIN_SECRET_KEY');
    if (!verified.isAdmin) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    req.user = verified;
    next();
  } catch (error) {
    console.error('Admin token verification error:', error);
    res.status(400).json({ error: 'Invalid token', details: error.message });
  }
};

app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"
  );
  next();
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/quiz', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'quiz.html'));
});

// routes
// login route 
app.post('/api/login', async (req, res) => {
  console.log('Login request received:', req.body);
  const { redditHandle, password } = req.body;
  
  if (!redditHandle || !password) {
      console.log('Missing reddit handle or password');
      return res.status(400).json({ error: 'Reddit handle and password are required' });
  }

  try {
      const user = await User.findOne({ where: { redditHandle } });
      console.log('User found:', user ? 'Yes' : 'No');
      
      if (!user) {
          console.log('User not found');
          return res.status(400).json({ error: 'User not found' });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      console.log('Password valid:', validPassword);
      
      if (!validPassword) {
          console.log('Invalid password');
          return res.status(400).json({ error: 'Invalid password' });
      }

      const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
      res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
      
      const responseData = {
          message: 'Logged in successfully',
          isAdmin: user.isAdmin,
          redirectUrl: user.isAdmin ? '/admin' : '/quiz'
      };
      console.log('Sending response:', responseData);
      res.json(responseData);
  } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// registration route 
app.post('/api/register', [
  body('redditHandle').notEmpty().withMessage('Reddit handle is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { firstName, lastName, redditHandle, email, password } = req.body;
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ 
      where: { 
        [Sequelize.Op.or]: [
          { redditHandle },
          { email }
        ]
      } 
    });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this Reddit handle or email' });
    }

    // Create new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      firstName,
      lastName,
      redditHandle,
      email,
      password: hashedPassword
    });

    // Create a JWT token
    const token = jwt.sign({ id: newUser.id, isAdmin: newUser.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Set the token as an HTTP-only cookie
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

    res.status(201).json({ 
      message: 'User registered successfully',
      redirectUrl: '/quiz'
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { redditHandle, password } = req.body;
  
  console.log('Login attempt:', { redditHandle, password });

  if (!redditHandle || !password) {
      return res.status(400).json({ error: 'Reddit handle and password are required' });
  }

  try {
      const user = await User.findOne({ where: { redditHandle } });
      if (!user) {
          return res.status(400).json({ error: 'User not found' });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
          return res.status(400).json({ error: 'Invalid password' });
      }

      // Create a JWT token
      const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });

      // Set the token as an HTTP-only cookie
      res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

      // Return user info and redirect URL
      res.json({ 
          message: 'Logged in successfully',
          isAdmin: user.isAdmin,
          redirectUrl: user.isAdmin ? '/admin' : '/quiz'
      });
  } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get all questions (admin only)
app.get('/api/admin/questions', verifyAdminToken, async (req, res) => {
  try {
    const questions = await Question.findAll();
    res.json(questions);
  } catch (error) {
    console.error('Get questions error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Leaderboard route
app.get('/api/leaderboard', async (req, res) => {
  try {
    const users = await User.findAll({
      where: {
        quizzesTaken: { [Sequelize.Op.gt]: 0 }
      },
      attributes: ['firstName', 'lastName', 'redditHandle', 'quizzesTaken', 'totalCorrect'],
    });

    const leaderboard = users
      .map(user => ({
        name: user.firstName || user.lastName || user.redditHandle,
        quizzesTaken: user.quizzesTaken,
        totalCorrect: user.totalCorrect,
        percentCorrect: user.quizzesTaken > 0 
          ? ((user.totalCorrect / (user.quizzesTaken * 10)) * 100).toFixed(2)
          : 0
      }))
      .sort((a, b) => {
        if (b.percentCorrect !== a.percentCorrect) {
          return b.percentCorrect - a.percentCorrect;
        }
        return b.quizzesTaken - a.quizzesTaken;
      })
      .slice(0, 10);

    res.json(leaderboard);
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// registration route
app.post('/api/register', [
  body('redditHandle').notEmpty().withMessage('Reddit handle is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { firstName, lastName, redditHandle, password } = req.body;
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ where: { redditHandle } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this Reddit handle' });
    }

    // Create new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      firstName,
      lastName,
      redditHandle,
      password: hashedPassword
    });

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Login route with input validation
app.post('/api/login', async (req, res) => {
  const { redditHandle, password } = req.body;
  
  console.log('Login attempt:', { redditHandle, password });

  if (!redditHandle || !password) {
      return res.status(400).json({ error: 'Reddit handle and password are required' });
  }

  try {
      const user = await User.findOne({ where: { redditHandle } });
      console.log('User found:', user ? 'Yes' : 'No');
      
      if (!user) {
          return res.status(400).json({ error: 'User not found' });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      console.log('Password valid:', validPassword);
      
      if (!validPassword) {
          return res.status(400).json({ error: 'Invalid password' });
      }

      res.json({ message: 'Logged in successfully' });
  } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
  }
});

app.get('/api/users', async (req, res) => {
  try {
      const users = await User.findAll({
          attributes: ['id', 'firstName', 'lastName', 'redditHandle']
      });
      res.json(users);
  } catch (error) {
      console.error('Error fetching users:', error);
      res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Admin login route with input validation
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ where: { redditHandle: username, isAdmin: true } });
    if (!user) {
      return res.status(400).json({ error: 'Admin not found' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.id, isAdmin: true }, 'YOUR_ADMIN_SECRET_KEY', { expiresIn: '1h' });
    res.json({ token, message: 'Admin logged in successfully' });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', verifyAdminToken, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'firstName', 'lastName', 'redditHandle', 'email', 'quizzesTaken', 'totalCorrect', 'isAdmin']
    });
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Edit user (admin only)
app.put('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { firstName, lastName, redditHandle, email, isAdmin } = req.body;
  try {
    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await user.update({ firstName, lastName, redditHandle, email, isAdmin });
    res.json({ success: true, message: 'User updated successfully', user });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
  try {
    const userId = req.params.id;
    const result = await User.destroy({ where: { id: userId } });
    if (result === 1) {
      res.json({ success: true, message: 'User deleted successfully' });
    } else {
      res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get all questions (admin only)
app.get('/api/admin/questions', verifyAdminToken, async (req, res) => {
  try {
    const questions = await Question.findAll();
    res.json(questions);
  } catch (error) {
    console.error('Get questions error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Add a new question (admin only)
app.post('/api/admin/questions', verifyAdminToken, async (req, res) => {
  const { statement, answer } = req.body;
  try {
    const newQuestion = await Question.create({ statement, answer });
    res.status(201).json({ success: true, message: 'Question added successfully', question: newQuestion });
  } catch (error) {
    console.error('Add question error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Update a question (admin only)
app.put('/api/admin/questions/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { statement, answer } = req.body;
  try {
    const question = await Question.findByPk(id);
    if (!question) {
      return res.status(404).json({ error: 'Question not found' });
    }
    await question.update({ statement, answer });
    res.json({ success: true, message: 'Question updated successfully', question });
  } catch (error) {
    console.error('Update question error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Delete a question (admin only)
app.delete('/api/admin/questions/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await Question.destroy({ where: { id } });
    if (result === 1) {
      res.json({ success: true, message: 'Question deleted successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Question not found' });
    }
  } catch (error) {
    console.error('Delete question error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get questions for quiz (non-admin, requires regular user token)
app.get('/api/quiz/questions', verifyToken, async (req, res) => {
  try {
      const questions = await Question.findAll({
          order: Sequelize.literal('RANDOM()'),
          limit: 10,
          attributes: ['id'] // Only send the question ID, not the statement
      });
      res.json(questions);
  } catch (error) {
      console.error('Get quiz questions error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Submit quiz answers (non-admin, requires regular user token)
app.post('/api/quiz/submit', verifyToken, async (req, res) => {
  const { answers } = req.body; // answers should be an array of { questionId, userAnswer }
  try {
      let correctAnswers = 0;
      for (let answer of answers) {
          const question = await Question.findByPk(answer.questionId);
          if (question && question.answer === answer.userAnswer) {
              correctAnswers++;
          }
      }
      
      const user = await User.findByPk(req.user.id);
      await user.increment('quizzesTaken');
      await user.increment('totalCorrect', { by: correctAnswers });

      res.json({ 
          correctAnswers, 
          totalQuestions: answers.length,
          message: 'Quiz submitted successfully'
      });
  } catch (error) {
      console.error('Submit quiz error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
  }
});

app.get('/request-reset', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'request-reset.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// api/request-reset route 
app.post('/api/reset-password', [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }

  const { token, newPassword } = req.body;
  try {
    const user = await User.findOne({
      where: {
        resetPasswordToken: token,
        resetPasswordExpires: { [Sequelize.Op.gt]: Date.now() }
      }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await user.update({
      password: hashedPassword,
      resetPasswordToken: null,
      resetPasswordExpires: null
    });

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ error: 'An error occurred while resetting your password. Please try again later.' });
  }
});

app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  res.status(403).json({ error: 'Invalid CSRF token' });
});

async function sendResetEmail(email, resetToken, req) {
  // Create a test account at ethereal.email for development
  let testAccount = await nodemailer.createTestAccount();

  let transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false,
    auth: {
      user: testAccount.user,
      pass: testAccount.pass,
    },
  });

  // Construct the reset link
  let resetLink = `http://${req.headers.host}/reset-password?token=${resetToken}`;

  let info = await transporter.sendMail({
    from: '"Muscle Testing Quiz" <noreply@muscletestingquiz.com>',
    to: email,
    subject: "Password Reset Request",
    text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
           Please click on the following link, or paste this into your browser to complete the process:\n\n
           ${resetLink}\n\n
           If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    html: `<p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
           <p>Please click on the following link, or paste this into your browser to complete the process:</p>
           <p><a href="${resetLink}">${resetLink}</a></p>
           <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>`
  });

  console.log("Message sent: %s", info.messageId);
  console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));

  return info;
}

// Sync database and start server
sequelize.sync({ force: true }) // This will drop and recreate all tables
  .then(async () => {
    console.log('Database synced');

    try {
      // Create admin user
      const [adminUser, adminCreated] = await User.findOrCreate({
        where: { redditHandle: 'admin' },
        defaults: {
          firstName: 'Admin',
          lastName: 'User',
          redditHandle: 'admin',
          email: 'admin@example.com',
          password: bcrypt.hashSync('adminpassword', 10),
          isAdmin: true
        }
      });

      console.log(adminCreated ? 'Admin user created' : 'Admin user already exists');

      // Create a non-admin user
      const [regularUser, userCreated] = await User.findOrCreate({
        where: { redditHandle: 'user' },
        defaults: {
          firstName: 'Regular',
          lastName: 'User',
          redditHandle: 'user',
          email: 'user@example.com',
          password: bcrypt.hashSync('userpassword', 10),
          isAdmin: false
        }
      });

      console.log(userCreated ? 'Regular user created' : 'Regular user already exists');

      // Add initial questions
      const questions = [
        { statement: "The Earth is flat.", answer: false },
        { statement: "Water boils at 100 degrees Celsius at sea level.", answer: true },
        { statement: "The capital of France is London.", answer: false },
        { statement: "Humans have walked on the Moon.", answer: true },
        { statement: "Dolphins are a type of fish.", answer: false },
      ];

      await Question.bulkCreate(questions);
      console.log('Initial questions added');

      // Start the server
      app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
      });
    } catch (error) {
      console.error('Error during server startup:', error);
    }
  })
  .catch(error => console.error('Unable to sync database:', error));