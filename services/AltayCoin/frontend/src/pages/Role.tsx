import wheel1 from "/public/wheel4.png"
import wheel2 from "/public/wheel3.png"
import { useState } from "react";
import axios from "axios";
const Role: React.FC = () => {
const [coin, setCoin] = useState<number>(0)
const [coef, setCoef] = useState<number>(0)
const [coefWin, setCoefWin] = useState<number>(0)
const [coefLose, setCoefLose] = useState<number>(0)
const [coefNormal, setCoefNormal] = useState<number>(0)

const Role: () => void = async () =>{
    try {
      const response = await axios.post(`http://${window.location.hostname}:8080/users/role`, {coef, coin}, {
        headers: {
          Authorization: `${localStorage.getItem("token")}`,
        },
      })
      console.log(response.data)
      if(response.data.success){
        alert(response.data.message)
      }
    } catch (error) {
    }
  }
  return (
    <>
        <div className="roleZone">
            <div className="ruletka">
                <div className="coef">
                    <button type="button" onClick={()=>{
                        setCoef(1)
                        setCoefWin(0.4)
                        setCoefLose(0.3)
                        setCoefNormal(0.3)
                    }}>x1</button>
                    <button type="button" onClick={()=>{
                        setCoef(1.5)
                        setCoefWin(0.3)
                        setCoefLose(0.3)
                        setCoefNormal(0.4)
                    }}>x1.5</button>
                    <button type="button" onClick={()=>{
                        setCoef(2)
                        setCoefWin(0.2)
                        setCoefLose(0.4)
                        setCoefNormal(0.4)
                    }}>x2</button>
                </div>
                <div className="wheel">
                    <img className="wheel1" draggable="false" alt="Рулетка" src={wheel1}/>
                    <img className="wheel2" draggable="false" alt="Рулетка" src={wheel2}/>
                </div>
                <div className="coef">
                    <button type="button" onClick={()=>{
                        setCoef(2.5)
                        setCoefWin(0.3)
                        setCoefLose(0.6)
                        setCoefNormal(0.1)
                    }}>x2.5</button>
                    <button type="button" onClick={()=>{
                        setCoef(3)
                        setCoefWin(0.2)
                        setCoefLose(0.8)
                        setCoefNormal(0)
                    }}>x3</button>
                    <button type="button" onClick={()=>{
                        setCoef(5)
                        setCoefWin(0.1)
                        setCoefLose(0.9)
                        setCoefNormal(0)
                    }}>x5</button>
                </div>
            </div>
            <div className="roleInfo">
                <div>
                    <span>Ставка: </span>
                    <input type="number" value={coin} onChange={(e)=>setCoin(e.target.valueAsNumber)} placeholder="Кол-во AC" />
                    <span> AC</span>
                    <div className="buttonRole">
                        <button onClick={()=>{Role()}}>Крутить!</button>
                    </div>
                </div>
                <div className="state">
                    <span><b>Шансы:</b></span>
                    <span>Выигрыш: {coefWin}</span>
                    <span>Проигрыш: {coefLose}</span>
                    <span>Нейтральный результат: {coefNormal}</span>
                </div>
            </div>
        </div>
    </>
  );
};

export default Role;
