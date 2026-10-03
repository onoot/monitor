import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import UserModel from '../models/Users.js';

export default async (req, res, next) => {
    const token = (req.headers.authorization || '').replace(/Bearer\s?/, '');

    if (!token) {
        return res.status(403).json({ message: 'Нет доступа' });
    }

    try {
        // текущая логика: без подписи (decode)
        const decoded = jwt.decode(token);
        if (!decoded) {
            return res.status(403).json({ message: 'Нет доступа' });
        }

        let userId = decoded._id;
        // Обратная совместимость: если _id не ObjectId, считаем, что это email
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            const user = await UserModel.findOne({ email: userId }).select('_id isAdmin');
            if (!user) {
                return res.status(401).json({ message: 'Нет доступа' });
            }
            req.userId = user._id.toString();
            req.isAdmin = Boolean(user.isAdmin);
        } else {
            req.userId = userId;
            req.isAdmin = Boolean(decoded.isAdmin);
        }
        return next();
    } catch (err) {
        return res.status(403).json({ message: 'Нет доступа' });
    }
};