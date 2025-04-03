const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const axios = require('axios');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(bodyParser.json());

const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error(err.message);
    } else {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS preferences (
            user_id INTEGER PRIMARY KEY,
            categories TEXT,
            languages TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);
    }
});

const JWT_SECRET = 'YpurSecretKey';
const NEWS_API_KEY = '23329daa011940cda0fe8fea9875d14e';

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    jwt.verify(token.replace('Bearer ', ''), JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

app.post('/users/signup', [
    body('username').isEmail().withMessage('Username must be a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
        if (err) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        res.status(201).json({ message: 'User registered successfully' });
    });
});

app.post('/users/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    db.get("SELECT id, password FROM users WHERE username = ?", [username], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user.id, username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

app.get('/preferences', authenticateToken, (req, res) => {
    db.get("SELECT categories, languages FROM preferences WHERE user_id = ?", [req.user.userId], (err, preferences) => {
        if (err || !preferences) {
            return res.status(404).json({ error: 'Preferences not found' });
        }
        res.json(preferences);
    });
});

app.put('/preferences', authenticateToken, [
    body('categories').notEmpty().withMessage('Categories cannot be empty'),
    body('languages').notEmpty().withMessage('Languages cannot be empty')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { categories, languages } = req.body;
    db.run("INSERT INTO preferences (user_id, categories, languages) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET categories = ?, languages = ?", 
        [req.user.userId, categories, languages, categories, languages],
        function (err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to update preferences' });
            }
            res.json({ message: 'Preferences updated successfully' });
        }
    );
});

app.get('/news', authenticateToken, async (req, res) => {
    try {
        db.get("SELECT categories, languages FROM preferences WHERE user_id = ?", [req.user.userId], async (err, preferences) => {
            if (err || !preferences) {
                return res.status(404).json({ error: 'Preferences not set' });
            }
            
            const categories = preferences.categories.split(',').join(' OR ');
            const languages = preferences.languages.split(',').join(',');
            
            const response = await axios.get(`https://newsapi.org/v2/top-headlines`, {
                params: {
                    q: categories,
                    //language: languages,
                    apiKey: NEWS_API_KEY,
                }
            });
            
            res.json(response.data);
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch news', details: error.message });
    }
});

const server = app.listen(5000, () => {
    console.log('Server is running on port 5000');
});

module.exports = server; // Export the server instance

