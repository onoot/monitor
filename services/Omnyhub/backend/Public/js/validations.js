import {body} from 'express-validator';

export const loginValidation = [
    body('email','Неверный формат почты').isEmail(),
    body('password','Пароль должен быть минимум 5 символов').isLength({min: 5}),
];

export const registerValidation = [
    body('email','Неверный формат почты').isEmail(),
    body('password','Пароль должен быть минимум 5 символов').isLength({min: 5}),
    body('fullName', 'Имя должно иметь минимум 3 символа').isLength({min: 3}),
    body('avatarURL','Неверная ссылка на аватарку').optional().isURL(),
];

export const postCreateValidation = [
    body('title','Введите заголовок').isLength({min: 1}),
    body('text','Введите описание товара').isLength({min: 1}),
    body('tags').optional(),
    body('imageURL').optional(),
    body('prise','Введите цену').isLength({min: 1}),
];
