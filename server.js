

require('dotenv').config();

const express = require('express');
const path = require('path');
const app = express();
const { Sequelize, DataTypes } = require('sequelize');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
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
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
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
app.use(csrf({ cookie: true }));

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
  },
  totalQuestions: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  resetPasswordToken: DataTypes.STRING,
  resetPasswordExpires: DataTypes.DATE
});

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

// Sync database
sequelize.sync({ force: false }).then(() => console.log('Database synced'));

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.accessToken;
  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};
// Middleware to verify admin token
const verifyAdminToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
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

app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  res.status(403).json({ error: 'Invalid CSRF token' });
});

// Registration route
app.post('/api/register', [
  body('redditHandle').notEmpty().withMessage('Reddit handle is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
], async (req, res) => {
  console.log('Registration attempt:', req.body);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation errors:', errors.array());
    return res.status(400).json({ error: errors.array()[0].msg });
  }

  const { firstName, lastName, redditHandle, email, password } = req.body;
  try {
    console.log('Checking for existing user');
    const existingUser = await User.findOne({
      where: {
        [Sequelize.Op.or]: [
          { redditHandle },
          { email }
        ]
      }
    });
    if (existingUser) {
      console.log('User already exists');
      return res.status(400).json({ error: 'User already exists with this Reddit handle or email' });
    }

    console.log('Creating new user');
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      firstName,
      lastName,
      redditHandle,
      email,
      password: hashedPassword
    });

    console.log('User created:', newUser.id);

    const token = jwt.sign({ id: newUser.id, isAdmin: newUser.isAdmin }, JWT_SECRET, { expiresIn: '1h' });

    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

    res.status(201).json({
      message: 'User registered successfully',
      redirectUrl: '/quiz'
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error', details: error.message || 'Unknown error occurred' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { redditHandle, password } = req.body;
  
  try {
    const user = await User.findOne({ where: { redditHandle } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const accessToken = jwt.sign(
      { id: user.id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Store refresh token in database
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/refresh-token', // Restrict refresh token to specific path
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Determine the redirect URL
    const redirectUrl = user.isAdmin ? '/admin' : '/quiz';

    res.json({ 
      message: 'Logged in successfully',
      isAdmin: user.isAdmin,
      redirectUrl: redirectUrl
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Add a refresh token route
app.post('/api/refresh-token', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findOne({ where: { id: decoded.id, refreshToken } });

    if (!user) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    const accessToken = jwt.sign(
      { id: user.id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    res.json({ message: 'Token refreshed successfully' });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// Modify the logout route
app.post('/api/logout', (req, res) => {
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken', { path: '/api/refresh-token' });
  res.json({ message: 'Logged out successfully' });
});

app.use(csrf({ cookie: true }));

// Provide CSRF token to the client
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'frontend.html'));
});

// Admin login route
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

    const token = jwt.sign({ id: user.id, isAdmin: true }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, message: 'Admin logged in successfully' });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Serve the admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
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

app.get('/api/admin/questions/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const question = await Question.findByPk(id);
    if (!question) {
      return res.status(404).json({ error: 'Question not found' });
    }
    res.json(question);
  } catch (error) {
    console.error('Fetch question error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get questions for quiz (non-admin, requires regular user token)
app.get('/api/quiz/questions', verifyToken, async (req, res) => {
  try {
    const quizLength = 5; // Fixed quiz length
    
    const questions = await Question.findAll({
      order: Sequelize.literal('RANDOM()'),
      limit: quizLength,
      attributes: ['id', 'statement']
    });
    
    const response = {
      quizLength: quizLength,
      questions: questions
    };
    
    console.log('Sending response:', JSON.stringify(response, null, 2));
    
    res.json(response);
  } catch (error) {
    console.error('Get quiz questions error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

app.get('/api/leaderboard', async (req, res) => {
  try {
    const users = await User.findAll({
      where: {
        quizzesTaken: { [Sequelize.Op.gt]: 0 }
      },
      attributes: ['firstName', 'lastName', 'redditHandle', 'quizzesTaken', 'totalCorrect'],
      order: [['totalCorrect', 'DESC']],
      limit: 10
    });

    const leaderboard = users.map(user => ({
      name: user.firstName || user.lastName || user.redditHandle,
      score: user.totalCorrect
    }));

    res.json(leaderboard);
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit quiz answers (non-admin, requires regular user token)
app.post('/api/quiz/submit', verifyToken, async (req, res) => {
  const { answers } = req.body;
  
  try {
      let correctAnswers = 0;
      const totalQuestions = answers.length;

      for (let answer of answers) {
          const question = await Question.findByPk(answer.questionId);
          if (question && question.answer === answer.userAnswer) {
              correctAnswers++;
          }
      }

      // Update user statistics
      const user = await User.findByPk(req.user.id);
      await user.increment('quizzesTaken');
      await user.increment('totalCorrect', { by: correctAnswers });
      await user.increment('totalQuestions', { by: totalQuestions });

      res.json({ 
          correctAnswers, 
          totalQuestions,
          message: 'Quiz submitted successfully'
      });
  } catch (error) {
      console.error('Submit quiz error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Password reset request route
app.post('/api/request-reset', [
  body('email').isEmail().withMessage('Valid email is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
  }

  const { email } = req.body;

  try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
          return res.status(404).json({ error: 'No user found with that email address' });
      }

      const resetToken = crypto.randomBytes(20).toString('hex');
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      await user.save();

      // Create a test account using Ethereal
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

      // Send email
      let info = await transporter.sendMail({
          from: '"Muscle Testing Quiz" <noreply@example.com>',
          to: user.email,
          subject: "Password Reset Request",
          text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                 Please click on the following link, or paste this into your browser to complete the process:\n\n
                 http://${req.headers.host}/reset/${resetToken}\n\n
                 If you did not request this, please ignore this email and your password will remain unchanged.\n`,
      });

      console.log("Message sent: %s", info.messageId);
      console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
      res.json({ message: 'An email has been sent to ' + user.email + ' with further instructions.' });
  } catch (error) {
      console.error('Password reset request error:', error);
      res.status(500).json({ error: 'An error occurred while processing your request' });
  }
});

// Password reset route
app.post('/api/reset-password', [
  body('token').notEmpty().withMessage('Token is required'),
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
          return res.status(400).json({ error: 'Password reset token is invalid or has expired' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      res.json({ message: 'Your password has been updated' });
  } catch (error) {
      console.error('Password reset error:', error);
      res.status(500).json({ error: 'An error occurred while resetting your password' });
  }
});

// Serve the quiz page
app.get('/quiz', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'quiz.html'));
});

// Sync database and start server
sequelize.sync({ force: false }) // Ensure tables are not dropped
  .then(async () => {
    console.log('Database synced');

    try {
      // Check if questions exist
      const questionCount = await Question.count();
      
      if (questionCount === 0) {
        // Add initial questions only if the table is empty
        const questions = [
          { statement: "The Earth is flat.", answer: false },
          { statement: "Water boils at 100 degrees Celsius at sea level.", answer: true },
          { statement: "The capital of France is London.", answer: false },
          { statement: "Humans have walked on the Moon.", answer: true },
          { statement: "Dolphins are a type of fish.", answer: false },
        ];

        await Question.bulkCreate(questions);
        console.log('Initial questions added');
      } else {
        console.log('Questions already exist, skipping initialization');
      }


        // Start the server
        app.listen(PORT, () => {
          console.log(`Server is running on port ${PORT}`);
        });
      } catch (error) {
        console.error('Error during server startup:', error);
      }
        // Error handling middleware
        app.use((err, req, res, next) => {
          console.error(err.stack);
          res.status(500).json({ error: 'Something went wrong!', details: err.message });
        });
      })
      .catch(error => console.error('Unable to sync database:', error));