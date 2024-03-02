require('dotenv').config({ path: './.env' });

const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const i18next = require('i18next');
const Backend = require('i18next-fs-backend');
const middleware = require('i18next-http-middleware');
const nodemailer = require('nodemailer');


i18next
  .use(Backend)
  .use(middleware.LanguageDetector)
  .init({
    fallbackLng: 'en',
    backend: {
      loadPath: './locales/{{lng}}/translation.json'
    }
  });

// Assuming the below imports are correctly pointing to your local files
const DB = require('../cfg/config');
const User = require('../models/User');
const { authUser, authRole } = require('./auth');

const app = express();
app.use(middleware.handle(i18next));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.set('views', path.join(__dirname, '..', 'views'));
app.set('view engine', 'ejs');

const transporter = nodemailer.createTransport({
    service: 'gmail', // or another email service
    auth: {
        user: "sushshiit@gmail.com", // Your email address
        pass: "gmuk ukpq fbrr cean" // Your email password
    }
});


app.get('/change-language', (req, res) => {
    const newLang = req.query.lng;
    res.cookie('i18next', newLang);
    res.redirect('back');
});

app.post('/send-email', (req, res) => {
    const { to, subject, text } = req.body; // Extract data from request body

    const mailOptions = {
        from: "sushshiit@gmail.com", // Sender address
        to, // List of receivers
        subject, // Subject line
        text, // Plain text body
        // html: "<b>Hello world?</b>", // html body (optional)
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            return res.status(500).json({ msg: 'Error sending email' });
        } else {
            console.log('Email sent: ' + info.response);
            return res.status(200).json({ msg: 'Email sent successfully' });
        }
    });
});

app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/signup', (req, res) => {
    res.render('user/signup');
});

app.get('/login', (req, res) => {
    res.render('user/login');
});

app.get('/', async (req, res) => {
    try {
        const users = await User.find();
        res.render('home', { users });
    } catch (error) {
        console.error(error);
        res.status(500).send(req.t('error_fetching_users'));
    }
});

app.get('/dashboard', authenticateToken, authUser, authRole('admin'), async (req, res) => {
    try {
        const users = await User.find();
        res.render('admin/dashboard', { users });
    } catch (error) {
        console.error(error);
        res.status(500).send(req.t('error_fetching_users'));
    }
});

app.post('/signup', async (req, res) => {
    const { username, password, gender, gmail } = req.body;
    if (!username || !password) {
        return res.status(400).send(req.t('username_password_required'));
    }

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send(req.t('user_exists'));
        }
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = new User({
            username,
            password: hashedPassword,
            gender,
            gmail,
        });

        await newUser.save();
        res.redirect('/login');
    } catch (error) {
        console.error(error);
        res.status(500).send(req.t('error_signup'));
    }
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send(req.t('username_password_required'));
    }

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).send(req.t('user_not_found'));
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send(req.t('invalid_credentials'));
        }

        const accessToken = jwt.sign({
            id: user._id,
            username: user.username,
            role: user.role
        }, process.env.ACCESS_TOKEN_SECRET);
        res.cookie('accessToken', accessToken, { httpOnly: true });

        res.redirect('/');
    } catch (error) {
        console.error(error);
        res.status(500).send(req.t('error_login'));
    }
});

function authenticateToken(req, res, next) {
    const token = req.cookies.accessToken;
    if (!token) {
        return res.status(401).send(req.t('access_token_required'));
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send(req.t('invalid_token'));
        }
        req.user = decoded;
        next();
    });
}

function sendEmail() {
    const emailData = {
        to: 'recipient@example.com',
        subject: 'Test Email',
        text: 'This is a test email sent from my web app.',
    };

    fetch('/send-email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(emailData),
    })
    .then(response => response.json())
    .then(data => console.log(data.msg))
    .catch(error => console.error('Error:', error));
}


app.delete('/user/:username', authenticateToken, async (req, res) => {
    try {
        const deletedUser = await User.deleteOne({ username: req.user.username });
        if (deletedUser.deletedCount === 1) {
            res.status(200).send(req.t('user_deleted_successfully'));
        } else {
            res.status(404).send(req.t('user_not_found'));
        }
    } catch (error) {
        console.error(error);
        res.status(500).send(req.t('error_deleting_user'));
    }
});

app.put('/user/:username', async (req, res) => {
    const { username } = req.params;
    const { newUsername, newRole } = req.body;
    try {
        const updatedUser = await User.findOneAndUpdate(
            { username },
            { username: newUsername, role: newRole },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).send(req.t('user_not_found'));
        }

        res.status(200).send(updatedUser);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send(req.t('error_updating_user'));
    }
});

const port = 3000;
app.listen(port, () => {
    console.log(`Server running on port: ${port}`);
});
