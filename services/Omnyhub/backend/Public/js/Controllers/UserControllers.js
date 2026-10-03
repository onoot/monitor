import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import express from 'express';


import UserModel from '../models/Users.js';

export const register = async(req,res)=>{
    try {
        const salt = await bcrypt.genSalt(10);
        const password = req.body.password;
        const hash = await bcrypt.hash(password, salt);
    
        const doc = new UserModel({
            email: req.body.email,
            fullName: req.body.fullName,
            avatarURL: req.body.avatarURL,
            cardNumber: req.body.cardNumber || '',
            passwordHash: hash,
        });
    
        const user = await doc.save();

        const token = jwt.sign({
            _id: user._id,
            isAdmin: user.isAdmin,
         },
        'secret123',
         {
           expiresIn: '30d',
         },
       );
        const {passwordHash, cardNumber, ...userData} = user._doc;
        // При регистрации не возвращаем cardNumber
        res.json({
            ...userData,
            token,
        });
    }catch(err){
        console.log(err);
        res.status(500).json({
            message: 'Не удалось зарегестрироваться',
        });
    }
};
export const login = async(req,res)=>{
    try {
        const user = await UserModel.findOne({ email: req.body.email });
        
        if (!user){
            return res.status(400).json({
                message: 'Сначала вам следует зарегестрироваться!',
            });
        }

        const isValidPass = await bcrypt.compare(req.body.password, user._doc.passwordHash);
        if(!isValidPass){
            return res.status(400).json({
                message: 'Неверный логин или пароль',
            });
        }

        const token = jwt.sign({
            _id: user.email,
            isAdmin: user.isAdmin,
         },
         'secret123',
         {
           expiresIn: '30d',
         },
        );

        const {passwordHash, cardNumber, ...userData} = user._doc;
        // При логине не возвращаем cardNumber
        res.json({
            ...userData,
            token,
        });

    } catch (err){
        console.log(err);
        res.status(500).json({
            message: ' Не удалось авторизоваться',
        });
    }
};
export const getMe = async(req,res)=>{
    try {
        const user = await UserModel.findById(req.userId);

        if (!user){
            return res.status(404).json({
                message: 'Пользователь не найден',
            });
        }

        const { passwordHash, ...userData } = user._doc;
        res.json(userData);
    } catch(err){
        console.log(err);
        res.status(500).json({
            message: 'Нет доступа',
        });
    }
};

export const getAll = async (req, res) => {
    try {
        const { q } = req.query;
        const filter = {};
        if (q && String(q).trim().length > 0) {
            const raw = String(q).trim();
            const escaped = raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            let regex;
            try {
                regex = new RegExp(escaped, 'i');
            } catch (_) {
                regex = undefined;
            }
            if (regex) {
                filter.$or = [
                    { fullName: regex },
                    { email: regex },
                ];
            }
        }

        // Определяем, является ли запрос от администратора (по токену, если он есть)
        let isAdminRequest = false;
        try {
            const authHeader = req.headers.authorization || '';
            const rawToken = authHeader.replace(/Bearer\s?/, '');
            if (rawToken) {
                const decoded = jwt.decode(rawToken, 'secret123');
                if (decoded && decoded.isAdmin) {
                    isAdminRequest = true;
                }
            }
        } catch (_) {
        }

        const projection = isAdminRequest ? '-passwordHash' : '-passwordHash -cardNumber';
        const users = await UserModel.find(filter, projection).sort({ createdAt: -1 }).lean();
        res.json(users);
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: 'Не удалось получить пользователей',
        });
    }
};

export const getById = async (req, res) => {
    try {
        const { id } = req.params;

        let isAdminRequest = false;
        try {
            const authHeader = req.headers.authorization || '';
            const rawToken = authHeader.replace(/Bearer\s?/, '');
            if (rawToken) {
                const decoded = jwt.verify(rawToken, 'secret123');
                if (decoded && decoded.isAdmin) {
                    isAdminRequest = true;
                }
            }
        } catch (_) {}

        const projection = isAdminRequest ? '-passwordHash' : '-passwordHash -cardNumber';
        const user = await UserModel.findById(id, projection).lean();
        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }
        return res.json(user);
    } catch (err) {
        console.log(err);
        return res.status(500).json({ message: 'Не удалось получить пользователя' });
    }
};