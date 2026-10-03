import axios from 'axios';

export const API_URL = 'http://localhost:4444'; // Адрес вашего бэкенда

const $api = axios.create({
  baseURL: API_URL,
});

// Автоматическая подстановка токена в заголовки
$api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  console.log('API Request:', config.url, config.method, config.data);
  return config;
});

// Обработка ответов
$api.interceptors.response.use(
  (response) => {
    console.log('API Response:', response.status, response.data);
    return response;
  },
  (error) => {
    console.error('API Error:', error.response ? error.response.data : error.message);
    return Promise.reject(error);
  }
);

export default $api;