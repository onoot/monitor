import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import $api, { API_URL } from '../api';
import '../styles/posts.css';

const Posts = ({ isAuth }) => {
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchPosts = async () => {
      try {
        setLoading(true);
        const response = await $api.get('/posts');
        setPosts(response.data);
        setError('');
      } catch (err) {
        console.error('Ошибка при загрузке постов:', err);
        setError('Не удалось загрузить посты. Попробуйте позже.');
      } finally {
        setLoading(false);
      }
    };

    fetchPosts();
  }, []);

  if (loading) {
    return <div className="loading-container">Загрузка постов...</div>;
  }

  if (error) {
    return <div className="error-container">{error}</div>;
  }

  return (
    <div className="posts-container">
      <h1 className="posts-title">Список объявлений</h1>
      
      {isAuth && (
        <div className="create-post-button-container">
          <Link to="/create-post" className="create-post-button">
            Создать новое объявление
          </Link>
        </div>
      )}
      
      {posts.length === 0 ? (
        <div className="no-posts-message">
          <p>Пока нет ни одного объявления</p>
          {isAuth && (
            <p>Создайте первое объявление!</p>
          )}
        </div>
      ) : (
        <div className="posts-grid">
          {posts.map((post) => (
            <div key={post._id} className="post-card">
              {post.imageURL && (
                <div className="post-image-container">
                  <img 
                    src={`${API_URL}${post.imageURL}`} 
                    alt={post.title}
                    className="post-image"
                  />
                </div>
              )}
              <div className="post-content">
                <h2 className="post-title">{post.title}</h2>
                <div className="post-price">{post.prise}</div>
                <p className="post-text">{post.text.length > 100 ? `${post.text.slice(0, 100)}...` : post.text}</p>
                {post.tags && post.tags.length > 0 && (
                  <div className="post-tags">
                    {post.tags.map((tag, index) => (
                      <span key={index} className="post-tag">{tag}</span>
                    ))}
                  </div>
                )}
                <div className="post-meta">
                  <span className="post-author">Автор: {post.user.fullName}</span>
                  <span className="post-date">
                    {new Date(post.createdAt).toLocaleDateString('ru-RU')}
                  </span>
                </div>
                <Link to={`/posts/${post._id}`} className="read-more-button">
                  Подробнее
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
      
      <div className="back-link-container">
        <Link to="/" className="back-link">
          Вернуться на главную
        </Link>
      </div>
    </div>
  );
};

export default Posts;


