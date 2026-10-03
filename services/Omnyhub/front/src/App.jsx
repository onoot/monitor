import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import HomePage from './components/homepage';
import Register from './components/register';
import Auth from './components/auth';
import Posts from './components/posts';
import PostDetail from './components/postDetail';
import CreatePost from './components/createPost';
import EditPost from './components/editPost';
import Users from './components/users';
import UserDetail from './components/UserDetail';
import Profile from './components/Profile';
import $api from './api';
import './index.css';

const App = () => {
  const [isAuth, setIsAuth] = useState(false);
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true); // Для проверки токена

  // Проверяем авторизацию при загрузке приложения
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        setIsLoading(false);
        return;
      }
      
      try {
        console.log('Проверка авторизации...');
        const response = await $api.get('/auth/me');
        console.log('Получены данные пользователя:', response.data);
        setIsAuth(true);
        setUser(response.data); // Сохраняем данные пользователя
      } catch (err) {
        console.error('Ошибка проверки авторизации:', err);
      } finally {
        setIsLoading(false);
      }
    };
    
    checkAuth();
  }, []);

  // Если идёт проверка токена, показываем заглушку
  if (isLoading) {
    return <div className="loading-container">Загрузка...</div>;
  }

  return (
    <Router>
      <Routes>
        {/* Главная страница */}
        <Route path="/" element={<HomePage isAuth={isAuth} user={user} />} />
        
        {/* Авторизация и регистрация */}
        <Route 
          path="/auth" 
          element={isAuth ? <Navigate to="/" /> : <Auth setIsAuth={setIsAuth} />} 
        />
        <Route 
          path="/register" 
          element={isAuth ? <Navigate to="/" /> : <Register />} 
        />
        
        {/* Страницы постов */}
        <Route path="/posts" element={<Posts isAuth={isAuth} />} />
        <Route path="/posts/:id" element={<PostDetail isAuth={isAuth} userId={user?._id} />} />
        
        {/* Создание и редактирование постов (только для авторизованных) */}
        <Route 
          path="/create-post" 
          element={isAuth ? <CreatePost /> : <Navigate to="/auth" />} 
        />
        <Route 
          path="/edit-post/:id" 
          element={isAuth ? <EditPost /> : <Navigate to="/auth" />} 
        />
        
        {/* Список пользователей */}
        <Route path="/users" element={<Users isAuth={isAuth} />} />
        <Route path="/users/:id" element={<UserDetail />} />

        {/* Профиль */}
        <Route path="/profile" element={isAuth ? <Profile /> : <Navigate to="/auth" />} />
      </Routes>
    </Router>
  );
};

export default App;