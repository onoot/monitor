import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import './assets/css/game.css';
import Profile from "./pages/Profile";
import Earn from "./pages/Earn";
import Upgrades from "./pages/Upgrades";
import Table from "./pages/Table";
import Role from "./pages/Role";
import Autch from "./pages/Autch";
import Navbar from "./components/Navbar";
import axios from "axios";

const AppContent = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const location = useLocation(); // Теперь useLocation() находится внутри Router

  // Проверяем наличие токена при загрузке страницы
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      setIsAuthenticated(true);
    }
  }, []);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await axios.get(`http://${window.location.hostname}:8080/users/check-token`, {
          headers: {
            Authorization: `${localStorage.getItem("token")}`,
          },
        });

        if (response.data.success) {
          setIsAuthenticated(true);
        } else {
          setIsAuthenticated(false);
          localStorage.removeItem("token");
        }
      } catch (error) {
        setIsAuthenticated(false);
        localStorage.removeItem("token");
      }
    };

    checkAuth();
  }, [location.pathname]); // Обновление при изменении маршрута

  return (
    <>
      {isAuthenticated && <Navbar setIsAuthenticated={setIsAuthenticated} />}
      <Routes>
        {isAuthenticated ? (
          <>
            <Route path="/profile" element={<Profile />} />
            <Route path="/earn" element={<Earn />} />
            <Route path="/upgrades" element={<Upgrades />} />
            <Route path="/table" element={<Table />} />
            <Route path="/role" element={<Role />} />
            <Route path="*" element={<Navigate to="/profile" />} />
          </>
        ) : (
          <>
            <Route path="/autch" element={<Autch setIsAuthenticated={setIsAuthenticated} />} />
            <Route path="*" element={<Navigate to="/autch" />} />
          </>
        )}
      </Routes>
    </>
  );
};

const App = () => {
  return (
    <Router>
      <AppContent /> 
    </Router>
  );
};

export default App;
