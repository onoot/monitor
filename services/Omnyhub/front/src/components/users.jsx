import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import $api from '../api';
import '../styles/users.css';

const Users = ({ isAuth }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [queryInput, setQueryInput] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    const fetchUsers = async () => {
      try {
        setLoading(true);
        const response = await $api.get('/users', {
          params: { q: searchQuery || undefined },
          signal: controller.signal,
        });
        setUsers(response.data);
        setError('');
      } catch (err) {
        if (err.name !== 'CanceledError') {
          console.error('Ошибка при загрузке пользователей:', err);
          setError('Не удалось загрузить список пользователей. Попробуйте позже.');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchUsers();
    return () => controller.abort();
  }, [searchQuery]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setSearchQuery(queryInput);
  };

  if (loading) {
    return <div className="loading-container">Загрузка пользователей...</div>;
  }

  return (
    <div className="users-page">
      <div className="users-header">
        <h1>Пользователи</h1>
        <Link to="/" className="back-link">На главную</Link>
      </div>

      <div className="users-search">
        <form onSubmit={handleSearchSubmit}>
          <input
            type="text"
            placeholder="Поиск по имени или email"
            value={queryInput}
            onChange={(e) => setQueryInput(e.target.value)}
          />
          <button type="submit">Найти</button>
        </form>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="users-container">
        {users.length === 0 ? (
          <div className="no-users">Пользователи не найдены</div>
        ) : (
          users.map((user) => (
            <div className="user-card" key={user._id}>
              <div className="user-avatar">
                {user.avatarURL ? (
                  <img 
                    src={`http://localhost:4444${user.avatarURL}`} 
                    alt={`${user.fullName || user.email} аватар`} 
                  />
                ) : (
                  <div className="default-avatar">
                    {(user.fullName ? user.fullName[0] : user.email[0]).toUpperCase()}
                  </div>
                )}
              </div>
              <div className="user-info">
                <h3 className="user-name">{user.fullName || 'Нет имени'}</h3>
                {user.isAdmin && (
                  <div className="user-role">Админ</div>
                )}
                <p className="user-email">{user.email}</p>
                {user.cardNumber && (
                  <p className="user-card">Карта: {user.cardNumber}</p>
                )}
                {user.createdAt && (
                  <p className="user-date">
                    Дата регистрации: {new Date(user.createdAt).toLocaleDateString()}
                  </p>
                )}
                <Link to={`/users/${user._id}`} className="user-link">Профиль</Link>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Users; 