import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

dotenv.config(); // Load environment variables

const app = express();
app.use(express.json());
app.use(cors({
    origin: [process.env.CLIENT_URL], // Ensure this is the correct client URL
    methods: ["POST", "GET", "UPDATE"],
    credentials: true
}));
app.use(cookieParser());

//add prefix to all routes
const router = express.Router();
app.use('/api', router);


const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
    } else {
        console.log('Connected to the MySQL database');
    }
});

const saltRounds = 10;

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({Error: "You are not authenticated!"});
    } else {
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({Error: "Token is not valid or has expired!"});
            } else {
                req.name = decoded.name;
                next();
            }
        });
    }
};

// Get user info
router.get('/user', verifyUser, (req, res) => {
    return res.json({Status: "Success", name: req.name});
});

// Register user
router.post('/register', (req, res) => {
    const {name, email, password} = req.body;

    // Check if the email already exists
    const checkEmailSql = "SELECT * FROM login WHERE email = ?";
    db.query(checkEmailSql, [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({Error: "Database query error"});
        }
        if (results.length > 0) {
            return res.status(409).json({Error: "Email already exists"});
        }

        // Proceed with registration
        const saltRounds = 10;
        bcrypt.hash(password.toString(), saltRounds, (err, hash) => {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).json({Error: "Error hashing password"});
            }

            const sql = "INSERT INTO login (name, email, password, verificationToken, verified) VALUES (?, ?, ?, ?, ?)";
            const values = [
                name,
                email,
                hash,
                crypto.randomBytes(32).toString('hex'), // Generate verification token
                false // Default to not verified
            ];

            db.query(sql, values, (err, result) => {
                if (err) {
                    console.error('Error inserting data into database:', err);
                    return res.status(500).json({Error: "Insert data error in server"});
                }

                // Send verification email
                const verificationLink = `${process.env.CLIENT_URL}/verify-email?token=${values[3]}`;
                sendVerificationEmail(email, verificationLink);

                return res.json({Status: "Success"});
            });
        });
    });
});


// Login endpoint :app.post('/api/logout', (req, res)
router.post('/login', (req, res) => {
    const {email, password} = req.body;
    const sql = "SELECT * FROM login WHERE email = ?";
    db.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.json({Error: "Database query error"});
        }
        if (results.length === 0) return res.json({Error: "User not found"});

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.json({Error: "Error comparing passwords"});
            if (!isMatch) return res.json({Error: "Incorrect password"});

            if (!user.verified) {
                return res.json({Error: "Email not verified"});
            }

            const name = user.name;
            const token = jwt.sign({name}, process.env.JWT_SECRET, {expiresIn: '1d'});
            res.cookie('token', token, {httpOnly: true});

            return res.json({Status: "Success"});
        });
    });
});

// Logout endpoint
router.post('/logout', (req, res) => {
    res.clearCookie('token', {httpOnly: true});
    return res.json({Status: "Success"});
});

router.get('/verify-email', (req, res) => {
    console.log('Verify email endpoint hit');
    const {token} = req.query;
    console.log('Received token:', token);
    if (!token) {
        return res.status(400).json({Error: "Verification token is missing"});
    }

    const sql = "UPDATE login SET verified = 1 WHERE verificationToken = ?";
    db.query(sql, [token], (err, result) => {
        if (err) {
            console.error('Error updating verification status:', err);
            return res.status(500).json({Error: "Internal server error during verification"});
        }

        if (result.affectedRows === 0) {
            return res.status(400).json({Error: "Invalid or expired token"});
        }

        return res.json({Status: "Email verified successfully"});
    });
});


// Function to send verification email
const sendVerificationEmail = (to, link) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER, // your email address
            pass: process.env.EMAIL_PASS  // your email password
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: to,
        subject: 'Email Verification',
        html: `
            <p>You have requested to verify your email. Click the link below to set a new password:</p>
            <a href="${link}">Click Here to Verify Your Email</a>
            <p>If you did not request this, please ignore this email.</p>
        `
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
};

const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
