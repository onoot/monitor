import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import $api from '../api';
import '../index.css';

const Auth = ({ setIsAuth }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (!email || !password) {
      setError('Необходимо заполнить все поля');
      return;
    }
    
    try {
      console.log('Отправка данных для входа:', { email, password });
      const response = await $api.post('/auth', { email, password });
      console.log('Ответ от сервера:', response.data);
      
      // Сохраняем токен
      const token = response.data.token;
      if (!token) {
        setError('Токен не получен от сервера');
        return;
      }
      
      localStorage.setItem('token', token);
      
      // Обновляем состояние авторизации
      setIsAuth(true);
      
      // Переходим на главную
      navigate('/');
    } catch (err) {
      console.error('Ошибка при авторизации:', err);
      if (err.response) {
        console.error('Данные ошибки:', err.response.data);
        setError(err.response.data.message || 'Неверный email или пароль');
      } else if (err.request) {
        setError('Сервер не отвечает. Пожалуйста, проверьте подключение к интернету или попробуйте позже.');
      } else {
        setError('Ошибка при отправке запроса: ' + err.message);
      }
    }
  };

  return (
    <div className="auth-container">
      <h2>Вход в аккаунт</h2>
      <form className="auth-form" onSubmit={handleSubmit}>
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
        <button type="submit" className="auth-button">Войти</button>
        {error && <p className="auth-error">{error}</p>}
        <p className="auth-switch">
          Нет аккаунта? <Link to="/register">Зарегистрироваться</Link>
        </p>
      </form>
    </div>
  );
};

export default Auth;