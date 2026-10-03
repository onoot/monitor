import { JSX, useEffect, useRef, useState } from "react";
import axios from "axios"
import { useNavigate } from "react-router-dom"
import level from "/public/level/level1.png"

const Autch: React.FC <{ setIsAuthenticated: (auth: boolean) => void }> = ({ setIsAuthenticated }) => {

    const [activeMode, setActiveMode] = useState<string>("autch");
    const [username, setUsername] = useState<string>("");
    const [password, setPassword] = useState<string>("");
    const [login, setLogin] = useState<string>("");
    const [pass, setPass] = useState<string>("");
    const [repass, setRepass] = useState<string>("");
    const [userinfo, setUserinfo] = useState<string>("");
    const [invitecode, setInvitecode] = useState<string>("");
    const navigate = useNavigate();

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

    const handleLogin = async () => {
        try {
          console.log(window.location.hostname)
          const response = await axios.post(`http://${window.location.hostname}:8080/users/autch`, { username, password });
    
          if (response.data.success) {
            localStorage.setItem("token", response.data.token);
            setIsAuthenticated(true)
            navigate("/profile");
          } else {
            alert("Ошибка: " + response.data.message);
          }
        } catch (error) {
          alert(`Ошибка сервера: ${error}`);
        }
      };
    const handleReg = async () => {
      try {
        const response = await axios.post(`http://${window.location.hostname}:8080/users/reg`, { login, pass, repass, userinfo, invitecode })
        console.log(response)
        if(response.data.success){
          message(response.data.message, 30)
        } else{
          alert("Ошибка: " + response.data.message);
        }
      } catch (error) {
        alert(`Ошибка сервера: ${error}`);
      }
    }
      useEffect(() => {
        const checkAuth = async () => {
          const token = localStorage.getItem("token");
    
          if (!token) {
            setIsAuthenticated(false);
            return;
          }
        };
    
        checkAuth();
      }, []);

    const upgradesContent: Record<string, JSX.Element> = {
        autch: <>
            <form action="">
                <span>Логин</span>
                <input type="text" placeholder="Логин" value={username} onChange={(e)=>setUsername(e.target.value)}></input>
                <span>Пароль</span>
                <input type="password" placeholder="Пароль" value={password} onChange={(e)=>setPassword(e.target.value)}></input>
                <button type="button" onClick={()=>{handleLogin()}}>Вход</button>
            </form>
        </>,
        reg: <>
            <form action="">
                <span>Логин</span>
                <input type="text" value={login} onChange={(e)=>setLogin(e.target.value)} placeholder="Логин"></input>
                <span>Пароль</span>
                <input type="password" value={pass} onChange={(e)=>setPass(e.target.value)} placeholder="Пароль"></input>
                <span>Повторите пароль</span>
                <input type="password" value={repass} onChange={(e)=>setRepass(e.target.value)} placeholder="Пароль"></input>
                <span>Описание профиля</span>
                <input type="text" value={userinfo} onChange={(e)=>setUserinfo(e.target.value)} placeholder="Описание"></input>
                <span>Код приглашения (Не обязательно)</span>
                <input type="text" value={invitecode} onChange={(e)=>setInvitecode(e.target.value)} placeholder="Код приглашения"></input>
                <button type="button" onClick={()=>{handleReg()}}>Регистрация</button>
            </form>
        </>,
    }
    return (
      <>
        <div className="autch">
            <div className="autchHeader">
                <span className={activeMode == "reg" ? "active" : ""} onClick={()=>setActiveMode("reg")}>Регистрация</span>
                <span className={activeMode == "autch" ? "active" : ""} onClick={()=>setActiveMode("autch")}>Авторизация</span>
            </div>
            <div className="authBody">
                {upgradesContent[activeMode]}
            </div>
        </div>
        <div id="modal" style={styleModal}>
      <img draggable="false" src={level} alt="Аватар" />
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
    )
}

export default Autch;