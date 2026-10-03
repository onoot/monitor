import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import $api from '../api';
import '../index.css';

const Register = () => {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [avatarURL, setAvatarURL] = useState('');
  const [cardNumber, setCardNumber] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (!fullName || !email || !password) {
      setError('Все обязательные поля должны быть заполнены');
      return;
    }
    
    try {
      console.log('Отправка данных для регистрации:', { fullName, email, password, avatarURL, cardNumber });
      const response = await $api.post('/register', { 
        fullName, 
        email, 
        password,
        avatarURL: avatarURL || undefined,
        cardNumber
      });
      console.log('Ответ от сервера:', response.data);
      
      // Сохраняем токен
      const token = response.data.token;
      if (!token) {
        setError('Токен не получен от сервера');
        return;
      }
      
      localStorage.setItem('token', token);
      
      // Переходим на главную
      navigate('/');
    } catch (err) {
      console.error('Ошибка при регистрации:', err);
      if (err.response) {
        console.error('Данные ошибки:', err.response.data);
        setError(err.response.data.message || 'Ошибка регистрации. Возможно, пользователь с таким email уже существует.');
      } else if (err.request) {
        console.error('Нет ответа от сервера');
        setError('Сервер не отвечает. Пожалуйста, проверьте подключение к интернету или попробуйте позже.');
      } else {
        console.error('Ошибка запроса:', err.message);
        setError('Ошибка при отправке запроса: ' + err.message);
      }
    }
  };

  return (
    <div className="auth-container">
      <h2>Регистрация</h2>
      <form className="auth-form" onSubmit={handleSubmit}>
        <input
          value={fullName}
          onChange={(e) => setFullName(e.target.value)}
          placeholder="Полное имя"
          className="auth-input"
          required
        />
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
          className="auth-input"
          required
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Пароль"
          className="auth-input"
          required
        />
        <input
          value={avatarURL}
          onChange={(e) => setAvatarURL(e.target.value)}
          placeholder="URL аватара (необязательно)"
          className="auth-input"
        />
        <input
          value={cardNumber}
          onChange={(e) => setCardNumber(e.target.value)}
          placeholder="Номер карты"
          className="auth-input"
        />
        <button type="submit" className="auth-button">Зарегистрироваться</button>
        {error && <p className="auth-error">{error}</p>}
        <p className="auth-switch">
          Уже есть аккаунт? <Link to="/auth">Войти</Link>
        </p>
      </form>
    </div>
  );
};

export default Register;