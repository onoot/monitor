import { useState, useEffect, useRef } from "react";
import level1 from "/public/level/worklevel1.webp";
import level2 from "/public/level/worklevel2.webp";
import level3 from "/public/level/worklevel3.webp";
import level4 from "/public/level/worklevel4.webp";
import level5 from "/public/level/worklevel5.webp";
import flash from "/public/flash.png";
import clickEffect from "/public/coin.png";
import axios from "axios";
import { io, Socket } from "socket.io-client";

interface EffectData {
    id: number;
    x: number;
    y: number;
  }
const levelImages: Record<number, string> = {
  1: level1,
  2: level2,
  3: level3,
  4: level4,
  5: level5,
};
const Earn: React.FC = () => {
  const [click, setClick] = useState<number>(0)
  const [dohod, setDohod] = useState<number>(0)
  const [level, setLevel] = useState<number>(1)
  const [MAX_ENERGY, setMAX_ENERGY] = useState<number>(0)
  const [ENERGY, setENERGY] = useState<number>(0)
  const [REGEN_RATE, setREGEN_RATE] = useState<number>(0)
  const [INTERVAL_MS, setINTERVAL_MS] = useState<number>(1000)
  const [isClicked, setIsClicked] = useState<boolean>(false);
  const [effects, setEffects] = useState<EffectData[]>([]);

  const socketRef = useRef<Socket | null>(null);
  useEffect(() => {
    if (!socketRef.current) {
      socketRef.current = io(`http://${window.location.hostname}:8080`); // 🔹 Создаём соединение один раз
      console.log("✅ Подключено к серверу:", socketRef.current.id);
    }

    // Слушаем событие от сервера
    socketRef.current.on("clickUpdate", (data) => {
      console.log("📩 Данные от сервера:", data);
      setENERGY(data.energy.energy)
      
    });

    socketRef.current.on("putEnergy", (data) => {
      setENERGY(data.energy.energy)
      
    });

    return () => {
      socketRef.current?.disconnect(); // Отключаем сокет при размонтировании
      socketRef.current = null; // Очищаем ref
      console.log("❌ Отключено от сервера");
    };
  }, [socketRef]); // 🔹 `[]` гарантирует, что `useEffect` сработает только один раз
  const handleClick = (event: React.MouseEvent<HTMLDivElement>) => {
    if (socketRef.current){
      socketRef.current.emit("click", {
        Authorization: `${localStorage.getItem("token")}`,
    });
    }
    setIsClicked(true);
    if (ENERGY > 49) {
        const newEffect = {
            id: Date.now(),
            x: event.clientX,
            y: event.clientY,
          };
          setEffects(prev => [...prev, newEffect]);
          setTimeout(() => {
            setEffects(prev => prev.filter(effect => effect.id !== newEffect.id));
          }, 1000);
      }
    setTimeout(() => {
      setIsClicked(false);
    }, 300);
  };
  useEffect(() => {
    const interval = setInterval(() => {
      if (socketRef.current){
        socketRef.current.emit("putEnergy", {
          Authorization: `${localStorage.getItem("token")}`,
        });
      }
    }, INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);
  async function getEarn() {
    const response = await axios.get(`http://${window.location.hostname}:8080/users/earn`, {
      headers: {
        Authorization: `${localStorage.getItem("token")}`,
      },
    })
    if(response.data.success) {
        console.log(response.data.data)
        setENERGY(response.data.data.rows[0].value.energy.energy)
        setMAX_ENERGY(response.data.data.rows[0].value.energy.maxEnergy)
        setREGEN_RATE(response.data.data.rows[0].value.energy.energyGeneric)
        setLevel(response.data.data.rows[0].value.level)
        setDohod(response.data.data.rows[0].value.passive)
        setClick(response.data.data.rows[0].value.click)
    }else {
      alert(response.data.message)
    }
  }
  useEffect(()=>{
    getEarn()
  }, [])
  return (
    <div className="workContent">
      <div className="workZone">
        <img alt="workZone" draggable="false" src={levelImages[level] || level1} className={`energy-icon ${isClicked ? "clicked" : ""}`} onClick={handleClick}  />
      </div>
      {effects.map(effect => (
        <img 
          key={effect.id}
          src={clickEffect}
          alt="effect"
          className="floating-effect"
          style={{ left: effect.x, top: effect.y }}
        />
      ))}
      <div className="workInstruments">
        <div className="energy">
          <span>{ENERGY}</span><span>/</span><span>{MAX_ENERGY}</span>
          <img draggable="false" 
            src={flash} 
            alt="energy"
          />
        </div>
        <div className="dochod">
          <span>{dohod} AC/s</span>
        </div>
      </div>
    </div>
  );
};

export default Earn;
