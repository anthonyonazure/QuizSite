const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

// Connect to the SQLite database
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Error connecting to the database:', err.message);
    process.exit(1);
  }
  console.log('Connected to the SQLite database.');
});

// Sample questions
const questions = [
  {
    text: "Which muscle is responsible for shoulder abduction?",
    options: JSON.stringify(["Deltoid", "Biceps brachii", "Triceps brachii", "Pectoralis major"]),
    correctAnswer: 0
  },
  {
    text: "What is the primary function of the quadriceps?",
    options: JSON.stringify(["Knee flexion", "Knee extension", "Hip flexion", "Hip extension"]),
    correctAnswer: 1
  },
  {
    text: "Which muscle group is primarily responsible for plantar flexion?",
    options: JSON.stringify(["Tibialis anterior", "Gastrocnemius and Soleus", "Peroneus longus", "Extensor digitorum longus"]),
    correctAnswer: 1
  }
];

// Create the questions table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  text TEXT NOT NULL,
  options TEXT NOT NULL,
  correctAnswer INTEGER NOT NULL
)`, (err) => {
  if (err) {
    console.error('Error creating questions table:', err.message);
    db.close();
    process.exit(1);
  }

  // Insert questions
  const stmt = db.prepare('INSERT INTO questions (text, options, correctAnswer) VALUES (?, ?, ?)');
  
  questions.forEach((question) => {
    stmt.run(question.text, question.options, question.correctAnswer, (err) => {
      if (err) {
        console.error('Error inserting question:', err.message);
      }
    });
  });

  stmt.finalize((err) => {
    if (err) {
      console.error('Error finalizing statement:', err.message);
    } else {
      console.log('Questions have been added to the database.');
    }

    // Close the database connection
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err.message);
      } else {
        console.log('Database connection closed.');
      }

      // Delete this script
      fs.unlink(__filename, (err) => {
        if (err) {
          console.error('Error deleting script:', err.message);
        } else {
          console.log('This script has been deleted to prevent repeated additions.');
        }
      });
    });
  });
});
