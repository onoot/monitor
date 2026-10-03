// src/components/HomePage.jsx
import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import '../styles/text.css';
import '../index.css';
import $api from '../api';

const HomePage = ({ isAuth, user }) => {
    const navigate = useNavigate();

    const handleLogout = () => {
        localStorage.removeItem('token');
        window.location.reload();
    };

    return (
        <div>
            <h1 className='midlefull'>Omnyhub</h1>
            <div>
                <center>
                    <div>
                        <div>
                            <Link to="/posts">
                                <button className='sub'>
                                    Перейти к списку постов
                                </button>
                            </Link>
                        </div>
                        <div>
                            <Link to="/users">
                                <button className='sub'>
                                    Список пользователей
                                </button>
                            </Link>
                        </div>
                        {isAuth ? (
                            <>
                                <div className="user-greeting">
                                    <h3>Привет, {user?.fullName || 'Пользователь'}!</h3>
                                    <h3>Первый месяц пользования бесплатный!</h3>
                                    {user?.avatarURL && (
                                        <div className="user-avatar">
                                            <img src={user.avatarURL} alt="Аватар пользователя" />
                                        </div>
                                    )}
                                </div>
                                <div>
                                    <Link to="/profile">
                                        <button className='sub'>
                                            Мой профиль
                                        </button>
                                    </Link>
                                </div>
                                <div>
                                    <button className='sub' onClick={handleLogout}>
                                        Выйти
                                    </button>
                                </div>
                                <div>
                                    <Link to="/create-post">
                                        <button className='sub'>
                                            Создать новый пост
                                        </button>
                                    </Link>
                                </div>
                            </>
                        ) : (
                            <>
                                <div>
                                    <Link to='/auth'>
                                        <button className='sub'>
                                            Войти
                                        </button>
                                    </Link>
                                </div>
                                <div>
                                    <Link to='/register'>
                                        <button className='sub'>
                                            Регистрация
                                        </button>
                                    </Link>
                                </div>
                            </>
                        )}
                    </div>
                </center>
            </div>
        </div>
    );
}

export default HomePage;
