import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import $api, { API_URL } from '../api';
import '../styles/posts.css';

const PostDetail = ({ isAuth, userId }) => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [post, setPost] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchPost = async () => {
      try {
        setLoading(true);
        const response = await $api.get(`/posts/${id}`);
        setPost(response.data);
        setError('');
      } catch (err) {
        console.error('Ошибка при загрузке поста:', err);
        setError('Не удалось загрузить пост. Попробуйте позже.');
      } finally {
        setLoading(false);
      }
    };

    fetchPost();
  }, [id]);

  const handleDelete = async () => {
    if (window.confirm('Вы действительно хотите удалить это объявление?')) {
      try {
        await $api.delete(`/posts/${id}`);
        navigate('/posts');
      } catch (err) {
        console.error('Ошибка при удалении поста:', err);
        alert('Не удалось удалить объявление. Попробуйте позже.');
      }
    }
  };

  if (loading) {
    return <div className="loading-container">Загрузка объявления...</div>;
  }

  if (error) {
    return <div className="error-container">{error}</div>;
  }

  if (!post) {
    return <div className="error-container">Объявление не найдено</div>;
  }

  const isAuthor = isAuth && userId && post.user && post.user._id === userId;

  return (
    <div className="post-detail-container">
      <h1 className="post-detail-title">{post.title}</h1>
      
      <div className="post-detail-price">{post.prise}</div>
      
      <div className="post-detail-meta">
        <span className="post-detail-author">Автор: {post.user.fullName}</span>
        <span className="post-detail-date">
          {new Date(post.createdAt).toLocaleDateString('ru-RU')}
        </span>
      </div>
      
      {post.imageURL && (
        <div className="post-detail-image-container">
          <img 
            src={`${API_URL}${post.imageURL}`} 
            alt={post.title}
            className="post-detail-image"
          />
        </div>
      )}
      
      <div className="post-detail-content">
        {post.text.split('\n').map((paragraph, index) => (
          <p key={index}>{paragraph}</p>
        ))}
      </div>
      
      {post.tags && post.tags.length > 0 && (
        <div className="post-detail-tags">
          <h3>Теги:</h3>
          <div className="tags-container">
            {post.tags.map((tag, index) => (
              <span key={index} className="post-detail-tag">{tag}</span>
            ))}
          </div>
        </div>
      )}
      
      {isAuthor && (
        <div className="post-detail-actions">
          <Link to={`/edit-post/${id}`} className="edit-post-button">
            Редактировать
          </Link>
          <button onClick={handleDelete} className="delete-post-button">
            Удалить
          </button>
        </div>
      )}
      
      <div className="post-detail-navigation">
        <Link to="/posts" className="back-to-posts-button">
          Вернуться к списку объявлений
        </Link>
      </div>
    </div>
  );
};

export default PostDetail; 