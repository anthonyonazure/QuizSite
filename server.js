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

console.log('Server starting...');

const app = express();
let PORT = process.env.PORT || 5000;

const JWT_SECRET = process.env.JWT_SECRET;

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
  // ... (keep the existing database initialization code)
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

// ... (rest of the file remains unchanged)
