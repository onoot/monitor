import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import $api from '../api';
import '../styles/posts.css';

const EditPost = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [title, setTitle] = useState('');
  const [text, setText] = useState('');
  const [prise, setPrise] = useState('');
  const [tags, setTags] = useState('');
  const [image, setImage] = useState(null);
  const [imagePreview, setImagePreview] = useState('');
  const [currentImageUrl, setCurrentImageUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchPost = async () => {
      try {
        setLoading(true);
        const response = await $api.get(`/posts/${id}`);
        const post = response.data;
        
        setTitle(post.title);
        setText(post.text);
        setPrise(post.prise || '');
        setTags(post.tags ? post.tags.join(', ') : '');
        
        if (post.imageURL) {
          setCurrentImageUrl(`http://localhost:4444${post.imageURL}`);
        }
        
        setError('');
      } catch (err) {
        console.error('Ошибка при загрузке поста:', err);
        setError('Не удалось загрузить пост для редактирования. Попробуйте позже.');
      } finally {
        setLoading(false);
      }
    };

    fetchPost();
  }, [id]);

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImage(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!title.trim() || !text.trim() || !prise.trim()) {
      setError('Заполните все обязательные поля (заголовок, текст и цена)');
      return;
    }
    
    try {
      setSubmitting(true);
      
      // Обновляем данные поста
      const postData = {
        title,
        text,
        prise,
        tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      };
      
      console.log('Отправляемые данные для обновления:', postData);
      
      await $api.patch(`/posts/${id}`, postData);
      
      // Если есть новое изображение, загружаем его
      if (image) {
        const formData = new FormData();
        formData.append('image', image);
        
        await $api.post('/upload', formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        });
      }
      
      navigate(`/posts/${id}`);
    } catch (err) {
      console.error('Ошибка при обновлении поста:', err);
      setError(err.response?.data?.message || 'Не удалось обновить пост. Попробуйте позже.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <div className="loading-container">Загрузка поста...</div>;
  }

  return (
    <div className="edit-post-container">
      <h1 className="edit-post-title">Редактирование поста</h1>
      
      <form className="edit-post-form" onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="title">Заголовок*</label>
          <input
            type="text"
            id="title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="form-control"
            required
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="prise">Цена*</label>
          <input
            type="text"
            id="prise"
            value={prise}
            onChange={(e) => setPrise(e.target.value)}
            className="form-control"
            placeholder="Например: 1000 руб."
            required
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="text">Текст поста*</label>
          <textarea
            id="text"
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="form-control"
            rows="6"
            required
          ></textarea>
        </div>
        
        <div className="form-group">
          <label htmlFor="tags">Теги (через запятую)</label>
          <input
            type="text"
            id="tags"
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            className="form-control"
            placeholder="Например: электроника, гаджет, новый"
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="image">Изображение (необязательно)</label>
          {currentImageUrl && !imagePreview && (
            <div className="current-image-container">
              <p>Текущее изображение:</p>
              <img src={currentImageUrl} alt="Текущее изображение" className="current-image" />
            </div>
          )}
          
          <input
            type="file"
            id="image"
            accept="image/*"
            onChange={handleImageChange}
            className="form-control-file"
          />
          
          {imagePreview && (
            <div className="image-preview-container">
              <p>Новое изображение:</p>
              <img src={imagePreview} alt="Предпросмотр" className="image-preview" />
            </div>
          )}
        </div>
        
        {error && <div className="error-message">{error}</div>}
        
        <div className="form-actions">
          <button 
            type="submit" 
            className="submit-button" 
            disabled={submitting}
          >
            {submitting ? 'Сохранение...' : 'Сохранить изменения'}
          </button>
          
          <Link to={`/posts/${id}`} className="cancel-button">
            Отмена
          </Link>
        </div>
      </form>
    </div>
  );
};

export default EditPost; 