import { useState, useEffect } from "react";
import level1 from "/public/level/level1.png"
import level2 from "/public/level/level2.png"
import level3 from "/public/level/level3.png"
import level4 from "/public/level/level4.png"
import level5 from "/public/level/level5.png"
import coin from "/public/coin.png";
import axios from "axios";

const levelImages: Record<number, string> = {
  1: level1,
  2: level2,
  3: level3,
  4: level4,
  5: level5,
};

const Table: React.FC = () => {
   const [content, setContent] = useState<any>(<></>)
   async function getAllUsers(){ 
    try {
        const response = await axios.get(`http://${window.location.hostname}:8080/users/allusers`, {
          headers: {
            Authorization: `${localStorage.getItem("token")}`,
          },
        })
        setContent(response.data.rows.map((user:any, index:number)=>(
          <tr id={user.id}>
              <td>{index + 1}</td>
              <td>
              <img draggable="false" alt="Icon" src={levelImages[user.value.level] || level1} />
              <span>{user.value.login}</span>
              </td>
              <td>
              <span>{user.value.coin}</span>
              <img draggable="false" alt="Coin" src={coin} />
              </td>
          </tr>
      )))
      } catch (error) {
        console.log(error)
      }
    }
    useEffect(()=>{
        getAllUsers()
    }, [])
  return (
    <div className="tableLead">
      <table className="userTable">
        <thead>
            <tr>
                <th>#</th>
                <th>Игрок</th>
                <th>Состояние</th>
            </tr>
        </thead>
        <tbody>
            {content}
        </tbody>
      </table>
    </div>
  );
};

export default Table;
