import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import $api, { API_URL } from '../api';
import '../styles/users.css';

const UserDetail = () => {
  const { id } = useParams();
  const [user, setUser] = useState(null);
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      try {
        setLoading(true);
        const [u, p] = await Promise.all([
          $api.get(`/users/${id}`, { signal: controller.signal }),
          $api.get(`/users/${id}/posts`, { signal: controller.signal }),
        ]);
        setUser(u.data);
        setPosts(p.data);
        setError('');
      } catch (err) {
        if (err.name !== 'CanceledError') {
          console.error('Ошибка загрузки профиля:', err);
          setError('Не удалось загрузить профиль пользователя');
        }
      } finally {
        setLoading(false);
      }
    };
    load();
    return () => controller.abort();
  }, [id]);

  if (loading) return <div className="loading-container">Загрузка профиля...</div>;
  if (error) return <div className="error-message">{error}</div>;
  if (!user) return <div className="error-message">Пользователь не найден</div>;

  return (
    <div className="user-detail-page">
      <div className="user-header">
        <h1>{user.fullName || 'Пользователь'}</h1>
        <Link to="/users" className="back-link">Назад к пользователям</Link>
      </div>
      <div className="user-info-block">
        {user.avatarURL && (
          <img src={user.avatarURL} alt="Аватар" className="user-avatar-large" />
        )}
        <p>Email: {user.email}</p>
        {user.isAdmin && <p className="user-role">Админ</p>}
        {user.cardNumber && <p className="user-card">Карта: {user.cardNumber}</p>}
        {user.createdAt && (
          <p>Зарегистрирован: {new Date(user.createdAt).toLocaleDateString()}</p>
        )}
      </div>

      <h2>Объявления пользователя</h2>
      <div className="posts-grid">
        {posts.length === 0 ? (
          <div className="no-posts-message">Нет объявлений</div>
        ) : (
          posts.map((post) => (
            <div key={post._id} className="post-card">
              {post.imageURL && (
                <div className="post-image-container">
                  <img src={`${API_URL}${post.imageURL}`} alt={post.title} className="post-image" />
                </div>
              )}
              <div className="post-content">
                <h3 className="post-title">{post.title}</h3>
                <div className="post-price">{post.prise}</div>
                <p className="post-text">{post.text.length > 100 ? `${post.text.slice(0, 100)}...` : post.text}</p>
                <Link to={`/posts/${post._id}`} className="read-more-button">Подробнее</Link>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default UserDetail;





