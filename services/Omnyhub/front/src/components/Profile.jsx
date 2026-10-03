import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import $api, { API_URL } from '../api';
import '../styles/posts.css';

const Profile = () => {
  const navigate = useNavigate();
  const [me, setMe] = useState(null);
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      try {
        setLoading(true);
        const meResp = await $api.get('/auth/me', { signal: controller.signal });
        setMe(meResp.data);
        const postsResp = await $api.get(`/users/${meResp.data._id}/posts`, { signal: controller.signal });
        setPosts(postsResp.data);
        setError('');
      } catch (err) {
        if (err.name !== 'CanceledError') {
          setError('Не удалось загрузить профиль.');
        }
      } finally {
        setLoading(false);
      }
    };
    load();
    return () => controller.abort();
  }, []);

  const handleDelete = async (id) => {
    if (!window.confirm('Удалить объявление?')) return;
    try {
      await $api.delete(`/posts/${id}`);
      setPosts((prev) => prev.filter((p) => p._id !== id));
    } catch (e) {
      alert('Не удалось удалить');
    }
  };

  if (loading) return <div className="loading-container">Загрузка...</div>;
  if (error) return <div className="error-container">{error}</div>;
  if (!me) return <div className="error-container">Нет доступа</div>;

  return (
    <div className="posts-container">
      <h1 className="posts-title">Мои объявления</h1>
      <div className="create-post-button-container">
        <Link to="/create-post" className="create-post-button">Создать новое объявление</Link>
      </div>
      <div className="posts-grid">
        {posts.length === 0 ? (
          <div className="no-posts-message">У вас пока нет объявлений</div>
        ) : (
          posts.map((post) => (
            <div key={post._id} className="post-card">
              {post.imageURL && (
                <div className="post-image-container">
                  <img src={`${API_URL}${post.imageURL}`} alt={post.title} className="post-image" />
                </div>
              )}
              <div className="post-content">
                <h2 className="post-title">{post.title}</h2>
                <div className="post-price">{post.prise}</div>
                <p className="post-text">{post.text.length > 100 ? `${post.text.slice(0, 100)}...` : post.text}</p>
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <Link to={`/edit-post/${post._id}`} className="read-more-button">Редактировать</Link>
                  <button onClick={() => handleDelete(post._id)} className="delete-post-button">Удалить</button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Profile;


