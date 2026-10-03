import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import $api from '../api';
import '../styles/posts.css';

const CreatePost = () => {
  const navigate = useNavigate();
  const [title, setTitle] = useState('');
  const [text, setText] = useState('');
  const [prise, setPrise] = useState('');
  const [tags, setTags] = useState('');
  const [image, setImage] = useState(null);
  const [imagePreview, setImagePreview] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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
      setLoading(true);
      
      // Сначала, если есть изображение, загружаем его и получаем URL
      let uploadedImageUrl = '';
      if (image) {
        const formData = new FormData();
        formData.append('image', image);
        const uploadResp = await $api.post('/upload', formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        });
        uploadedImageUrl = uploadResp.data?.url || '';
      }

      // Подготавливаем данные поста, включая imageURL если есть
      const postData = {
        title,
        text,
        prise,
        tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
        imageURL: uploadedImageUrl || undefined,
      };
      
      console.log('Отправляемые данные:', postData);
      
      // Отправляем данные поста (уже с imageURL, если загружали)
      const response = await $api.post('/posts', postData);
      
      navigate(`/posts/${response.data._id}`);
    } catch (err) {
      console.error('Ошибка при создании поста:', err);
      setError(err.response?.data?.message || 'Не удалось создать пост. Попробуйте позже.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="create-post-container">
      <h1 className="create-post-title">Создание нового поста</h1>
      
      <form className="create-post-form" onSubmit={handleSubmit}>
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
          <input
            type="file"
            id="image"
            accept="image/*"
            onChange={handleImageChange}
            className="form-control-file"
          />
          
          {imagePreview && (
            <div className="image-preview-container">
              <img src={imagePreview} alt="Предпросмотр" className="image-preview" />
            </div>
          )}
        </div>
        
        {error && <div className="error-message">{error}</div>}
        
        <div className="form-actions">
          <button 
            type="submit" 
            className="submit-button" 
            disabled={loading}
          >
            {loading ? 'Создание...' : 'Создать пост'}
          </button>
          
          <Link to="/posts" className="cancel-button">
            Отмена
          </Link>
        </div>
      </form>
    </div>
  );
};

export default CreatePost; 