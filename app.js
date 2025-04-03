const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');

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

const JWT_SECRET = 'your_secret_key';

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    jwt.verify(token.replace('Bearer ', ''), JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
        if (err) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        res.status(201).json({ message: 'User registered successfully' });
    });
});

app.post('/login', (req, res) => {
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

app.put('/preferences', authenticateToken, (req, res) => {
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

app.listen(5000, () => {
    console.log('Server is running on port 5000');
});
