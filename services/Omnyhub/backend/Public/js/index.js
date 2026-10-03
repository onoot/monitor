import express from 'express';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import {validationResult} from 'express-validator'
// import *as from './utils/handleValidationsErrors.js'

import * as UserConrollers from './Controllers/UserControllers.js'
import *as PostControllers from './Controllers/PostConroller.js'
import {registerValidation, loginValidation, postCreateValidation} from './validations.js';
import UserModel from './models/Users.js';
import chekAuth from './utils/chekAuth.js';
import handleValidationsErrors from './utils/handleValidationsErrors.js';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://admin:password@mongodb:27017/mydatabase?authSource=admin';

// Подключение к MongoDB
mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ DB super - успешное подключение к MongoDB'))
    .catch((err) => console.log('❌ DB ne super - ошибка подключения:', err));

const app = express();

// Разрешаем CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});

const UPLOADS_DIR = path.resolve('uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (_, __, cb) =>{
        cb(null, UPLOADS_DIR)
    },
    filename: (_,file,cb)=>{
        cb(null, file.originalname);
    },
});

const upload = multer({storage});

app.use(express.json());
app.use('/uploads', express.static(UPLOADS_DIR));


app.post('/auth',loginValidation,handleValidationsErrors,UserConrollers.login);
app.post('/register',registerValidation,handleValidationsErrors,UserConrollers.register);
app.get('/auth/me',chekAuth,UserConrollers.getMe);

app.post('/upload',chekAuth, upload.single('image'), (req, res)=>{
    res.json({
        url: `/uploads/${req.file.originalname}`
    });
});

app.get('/posts', PostControllers.getAll);
app.get('/posts/:id',PostControllers.getOne);
app.post('/posts', chekAuth, postCreateValidation, handleValidationsErrors, PostControllers.create);
app.delete('/posts/:id',chekAuth,PostControllers.remove);
app.patch('/posts/:id', chekAuth, postCreateValidation, handleValidationsErrors, PostControllers.update);

// Users
app.get('/users', UserConrollers.getAll);
app.get('/users/:id', UserConrollers.getById);
app.get('/users/:id/posts', PostControllers.getByUser);

app.listen(4444, (err)=>{
    if (err){
        return console.log(err);
    }
    console.log('Server super!');
});

// Ensure admin exists on initialization
(async () => {
    try {
        const adminEmail = 'admin@example.com';
        const adminPassword = 'admin';
        const exists = await UserModel.findOne({ email: adminEmail }).select('_id');
        if (!exists) {
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(adminPassword, salt);
            await UserModel.create({
                email: adminEmail,
                fullName: 'admin',
                passwordHash: hash,
                isAdmin: true,
                cardNumber: ''
            });
            console.log('👑 Администратор создан: admin@example.com / admin');
        }
    } catch (e) {
        console.log('Не удалось создать администратора:', e.message);
    }
})();
