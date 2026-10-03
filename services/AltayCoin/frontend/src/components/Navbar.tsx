import { Link } from "react-router-dom";
import coin from "/public/coin.png"
import level1 from "/public/level/level1.png"
import level2 from "/public/level/level2.png"
import level3 from "/public/level/level3.png"
import level4 from "/public/level/level4.png"
import level5 from "/public/level/level5.png"
import { useNavigate } from "react-router-dom";
import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { io, Socket } from "socket.io-client";
const Navbar: React.FC<{setIsAuthenticated: (auth: boolean) => void }> = ({setIsAuthenticated}) => {
  const [level, setLevel] = useState<number>(1)
  const [coins, setCoins] = useState<number>(0)
  const levelImages: Record<number, string> = {
    1: level1,
    2: level2,
    3: level3,
    4: level4,
    5: level5,
  };
  const [styleModal, setStyleModal] = useState<Record<string,string>>({
    display:"none",
  })
  const [text, setText] = useState<string>('text')
  const [time, setTime] = useState<string>('0')
  const textRef = useRef<string>(text)
  useEffect(() => {
    textRef.current = text
  }, [text])
  
  function message(mess: string, timer: number = 0) {
    setText(mess)
    openModal(timer)
  }
  
  function openModal(timer: number = 0) {
    setTime(`${timer > 9 ? timer : '0' + timer}`)
    setStyleModal({ display: "block" })
  
    setTimeout(() => {
      timer -= 1
      if (textRef.current != '' && timer>0) {
        openModal(timer)
      } else {
        closeModal()
      }
    }, 1000)
  }
  
  function closeModal() {
    setText('')
    setStyleModal({ display: "none" })
  }
  const socketRef = useRef<Socket | null>(null);
    useEffect(() => {
      if (!socketRef.current) {
        socketRef.current = io(`http://${window.location.hostname}:8080`); // 🔹 Создаём соединение один раз
      }
      if (socketRef.current){
        socketRef.current.emit("joinRoom", {
          Authorization: `${localStorage.getItem("token")}`,
        });
      }
      // Слушаем событие от сервера
      socketRef.current.on("coinUpdate", (data) => {
        setCoins(data)
      });
      socketRef.current.on("levelUpdate", (data) => {
        setLevel(data)
      });
      socketRef.current.on("putCoins", (data)=>{
        message(`Пока тебя не было мы заработали ${data} AC`, 10)
      })
  
      return () => {
        socketRef.current?.disconnect(); // Отключаем сокет при размонтировании
        socketRef.current = null; // Очищаем ref
        console.log("❌ Отключено от сервера");
      };
    }, [socketRef]); // 🔹 `[]` гарантирует, что `useEffect` сработает только один раз

  const navigate = useNavigate()
  const getUser: () => void = async () =>{
    try {
      const response = await axios.get(`http://${window.location.hostname}:8080/users/info`, {
        headers: {
          Authorization: `${localStorage.getItem("token")}`,
        },
      })
      console.log(response.data)
      if(response.data.success){
        setLevel(response.data.data.rows[0].value.level)
        setCoins(response.data.data.rows[0].value.coin)
      }
    } catch (error) {
    }
  }
  function Exit() {
    navigate("/autch");
    localStorage.removeItem("token"); // Сохраняем токен
    setIsAuthenticated(false)
  }

  useEffect(()=>{
    getUser()
  }, [])
  return (
    <>
      <nav>
        <Link to="/profile" id="profile">
          <img draggable="false" src={levelImages[level] || level1} alt="Профиль" />
          <span>Профиль</span>
        </Link>
        <div id="navLinks">
          <Link to="/earn" >Заработок</Link>
          <Link to="/upgrades" >Улучшения</Link>
          <Link to="/table" >Таблица лидеров</Link>
          <Link to="/role" >Рулетка</Link>
        </div>
        <div id="balance">
          <span >{coins}</span>
          <img draggable="false" src={coin} alt="Монеты" />
          <button onClick={Exit}>Выход</button>
        </div>
      </nav>
      <div id="modal" style={styleModal}>
      <img draggable="false" src={levelImages[level] || level1} alt="Аватар" />
        <div className="message">
          <div className="content">
            <span>{text}</span>
          </div>
          <div className="load">
            <svg viewBox="0 0 36 36">
              <circle cx="18" cy="18" r="16" stroke="#fff" fill="none" stroke-width="3"
                stroke-dasharray="100" stroke-dashoffset="75" />
            </svg>
            <span>{time}</span>
          </div>
          <div onClick={closeModal} className="close">
            <div className="cl-btn-3">
                <span className="top"></span>
                <span className="bot"></span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default Navbar;