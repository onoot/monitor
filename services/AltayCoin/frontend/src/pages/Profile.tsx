import level1 from "/public/level/level1.png"
import level2 from "/public/level/level2.png"
import level3 from "/public/level/level3.png"
import level4 from "/public/level/level4.png"
import level5 from "/public/level/level5.png"
import { useEffect, useState } from "react";
import axios from "axios";

const levelImages: Record<number, string> = {
  1: level1,
  2: level2,
  3: level3,
  4: level4,
  5: level5,
};

const Profile: React.FC = () => {
  const [level, setLevel] = useState<number>(1)
  const [userName, setUserName] = useState<string>("")
  const [userInfo, setUserInfo] = useState<string>("")
  const [inviteCode, setInviteCode] = useState<string>("")
  const [inviter, setInviter] = useState<any>(<></>)
  const getUser: () => void = async () =>{
    try {
      const response = await axios.get(`http://${window.location.hostname}:8080/users/info`, {
        headers: {
          Authorization: `${localStorage.getItem("token")}`,
        },
      })
      if(response.data.success){
        setLevel(response.data.data.rows[0].value.level)
        setUserName(response.data.data.rows[0].value.login)
        setUserInfo(response.data.data.rows[0].value.info)
        setInviteCode(response.data.data.rows[0].value.invitecode)
        const inviterCode = response.data.data.rows[0].value.inviter
        try {
          const res = await axios.get(`http://${window.location.hostname}:8080/users/inviter`, {
            headers: {
              Authorization: `${localStorage.getItem("token")}`,
            },
            params: {
              inviterCode
            }
          })
          if(res.data.success){
            setInviter(<div>
              <div className="iconProfileInviter">
                <img draggable="false" src={levelImages[res.data.data.rows[0].value.level] || level1} alt="userIcon" />
              </div>
              <div className="userInfoInviter">
                <div id="userNameInviter">
                  <span>Ник: {res.data.data.rows[0].value.login}</span>
                </div>
                <div id="userInfoInviter">
                  <span>Информация: {res.data.data.rows[0].value.info}</span>
                </div>
                <div id="inviteCodeInviter">
                  <span>Код приглашения: {res.data.data.rows[0].value.invitecode}</span>
                </div>
                <div id="coinInviter">
                <span>Состояние: {res.data.data.rows[0].value.coin} AC</span>
                </div>
              </div>
            </div>)
          } else{

          }
        } catch (error) {
          
        }
      } else{
      }
    } catch (error) {
    }
  }
  useEffect(() => {
    getUser();
  }, []);
    return (
    <div className="content">
      <div className="iconProfile">
        <img draggable="false" src={levelImages[level] || level1} alt="userIcon" />
      </div>
      <div className="userInfo">
        <div id="userName">
          <span>Ник: {userName}</span>
        </div>
        <div id="userInfo">
          <span>Информация: {userInfo}</span>
        </div>
        <div id="inviteCode">
          <span>Код приглашения: {inviteCode}</span>
        </div>
        <div id="inviter">
          <span>Вас пригласил:</span>
          {inviter}
        </div>
      </div>
    </div>
    );
  }
  
  export default Profile;