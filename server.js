const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const path = require('path');

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'Frontend.html'));
});

// Serve the admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Set up SQLite database
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './database.sqlite'
});

// User Model
const User = sequelize.define('User', {
  firstName: DataTypes.STRING,
  lastName: DataTypes.STRING,
  redditHandle: {
    type: DataTypes.STRING,
    unique: true
  },
  password: DataTypes.STRING,
  quizzesTaken: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  totalCorrect: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  isAdmin: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
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

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, 'YOUR_SECRET_KEY'); // Replace with a secure secret key
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// Middleware to verify admin token
const verifyAdminToken = async (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, 'YOUR_ADMIN_SECRET_KEY'); // Replace with a secure admin secret key
    const user = await User.findByPk(verified.id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    req.user = user;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// Leaderboard route
app.get('/leaderboard', async (req, res) => {
  try {
    const users = await User.findAll({
      where: {
        quizzesTaken: { [Sequelize.Op.gt]: 0 }
      },
      attributes: ['firstName', 'lastName', 'redditHandle', 'quizzesTaken', 'totalCorrect'],
      order: [
        [Sequelize.literal('(CAST(totalCorrect AS FLOAT) / CAST(quizzesTaken AS FLOAT))'), 'DESC'],
        ['quizzesTaken', 'DESC']
      ],
      limit: 10
    });

    console.log('Fetched leaderboard data:', users.length, 'entries');

    const leaderboard = users.map(user => ({
      name: user.firstName || user.lastName || user.redditHandle,
      score: ((user.totalCorrect / user.quizzesTaken) * 100).toFixed(2)
    }));

    res.json(leaderboard);
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Register route
app.post('/register', async (req, res) => {
  const { firstName, lastName, redditHandle, password } = req.body;
  if (!redditHandle || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    const existingUser = await User.findOne({ where: { redditHandle } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      firstName,
      lastName,
      redditHandle,
      password: hashedPassword
    });
    const token = jwt.sign({ id: newUser.id }, 'YOUR_SECRET_KEY');
    res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { redditHandle, password } = req.body;

  try {
    const user = await User.findOne({ where: { redditHandle } });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.id }, 'YOUR_SECRET_KEY');
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin login route
app.post('/admin/login', async (req, res) => {
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

    const token = jwt.sign({ id: user.id }, 'YOUR_ADMIN_SECRET_KEY'); // Replace with a secure admin secret key
    res.json({ token });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users (admin only)
app.get('/admin/users', verifyAdminToken, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'firstName', 'lastName', 'redditHandle', 'quizzesTaken', 'totalCorrect', 'isAdmin']
    });
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete user (admin only)
app.delete('/admin/users/:id', verifyAdminToken, async (req, res) => {
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
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all questions (admin only)
app.get('/admin/questions', verifyAdminToken, async (req, res) => {
  try {
    const questions = await Question.findAll();
    res.json(questions);
  } catch (error) {
    console.error('Get questions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add a new question (admin only)
app.post('/admin/questions', verifyAdminToken, async (req, res) => {
  const { statement, answer } = req.body;
  try {
    const newQuestion = await Question.create({ statement, answer });
    res.status(201).json(newQuestion);
  } catch (error) {
    console.error('Add question error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update a question (admin only)
app.put('/admin/questions/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { statement, answer } = req.body;
  try {
    const question = await Question.findByPk(id);
    if (!question) {
      return res.status(404).json({ error: 'Question not found' });
    }
    await question.update({ statement, answer });
    res.json(question);
  } catch (error) {
    console.error('Update question error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a question (admin only)
app.delete('/admin/questions/:id', verifyAdminToken, async (req, res) => {
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
    res.status(500).json({ error: 'Server error' });
  }
});

// Get questions for quiz (non-admin, requires regular user token)
app.get('/quiz/questions', verifyToken, async (req, res) => {
  try {
    const questions = await Question.findAll({
      order: Sequelize.literal('RANDOM()'),
      limit: 10,
      attributes: ['id', 'statement']
    });
    res.json(questions);
  } catch (error) {
    console.error('Get quiz questions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit quiz answers (non-admin, requires regular user token)
app.post('/quiz/submit', verifyToken, async (req, res) => {
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
    res.status(500).json({ error: 'Server error' });
  }
});

// Sync database and start server
sequelize.sync({ force: true }) // Use { force: true } only in development to reset the database on each run
  .then(() => {
    console.log('Database synced');
    // Create an admin user
    return User.create({
      firstName: 'Admin',
      lastName: 'User',
      redditHandle: 'admin',
      password: bcrypt.hashSync('adminpassword', 10),
      isAdmin: true
    });
  })
  .then(() => {
    // Add some initial questions
    return Question.bulkCreate([
      { statement: "The Earth is flat.", answer: false },
      { statement: "Water boils at 100 degrees Celsius at sea level.", answer: true },
      { statement: "The capital of France is London.", answer: false },
      { statement: "Humans have walked on the Moon.", answer: true },
      { statement: "Dolphins are a type of fish.", answer: false },
    ]);
  })
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch(error => console.error('Unable to sync database:', error));

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Server error', details: err.message });
});