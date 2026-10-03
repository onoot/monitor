import { Injectable } from '@nestjs/common';
const NodeCouchDb = require('node-couchdb');
import { JwtService } from '@nestjs/jwt';
import { createHash } from 'crypto';

const db = new NodeCouchDb({
    host: 'db',
    protocol: 'http',
    port: 5984,
    auth: {
        user: 'admin',
        pass: 'admin'
    }
});

const upgradeCoef: Record<string, number[]> = {
  "mouse": [2, 2.4],
  "keyboard": [2, 2.2],
  "monitor": [2, 2.3],
  "kreslo": [1.8, 2],
  "cpu": [1.2, 1.4],
  "videocard": [1.2, 1.3],
  "proc": [1.2, 1.5],
  "hydra": [1.5, 2],
  "burp": [1.5, 1.9],
  "sqlmap": [1.4, 2],
  "wireshark": [1.8, 2.5],
  "nmap": [1.5, 2.6],
  "hashcat": [1.3, 2],
  "nicto": [1.3, 2],
  "metasploit": [1.4, 2.4],
  "radare2": [1.5, 2.8],
  "netcat": [1.3, 2.2],
  "mainer": [2, 2.6],
  "scam": [1.5, 1.7],
  "darknet": [2, 2.7],
  "fisching": [1.5, 2],
  "reket": [2.2, 2.6],
  "backdoor": [2, 2.4],
  "carding": [1.8, 2.2],
};

@Injectable()
export class UsersService {
  constructor(private readonly jwtService: JwtService) {}
    async getUserInfo(user): Promise<any> {
      try {
        console.log(user)
        const { data } = await db.get('users', '_design/users/_view/getInfo', { key: user.id });
        return {success:true , data};
      } catch (err) {
        console.error("Ошибка при получении пользователя:", err);
        return { message: "Не удалось получить данные о пользователе." };
      }
    }

    async getUserInfoId(): Promise<any> {
        try {
          const { data } = await db.get('users', '_design/users/_view/getInfo', { key:"4a011662fe8a0596b964ed0f3d00065b" });
          return {success:true , data};
        } catch (err) {
          console.error("Ошибка при получении пользователя:", err);
          return { message: "Не удалось получить данные о пользователе." };
        }
      }

    async getUserUpgrades(user): Promise<any> {
      try {
        const { data } = await db.get('users', '_design/users/_view/getUpgrades', { key:user.id });
        return {success:true,data};
      } catch (err) {
        console.error("Ошибка при получении улучшений пользователя:", err);
        return { message: "Не удалось получить улучшения пользователя." };
      }
    }
    async role(user, body): Promise<any> {
      try {
        let { data } = await db.get('users', user.id );
        console.log(body)
        let randomNum = Math.floor(Math.random() * (9 - 0 + 1)) + 0;
        console.log(randomNum)
        if(body.coin<=data.coin){
          switch (body.coef){
            case 1:
              if(randomNum <= 3){
                await roleWin(user.id, body.coin, body.coef)
                return {success:true, message:"Win"};
              } else if(randomNum <= 6){
                await roleLose(user.id, body.coin)
                return {success:true, message:"lose"};
              } else{
                return {success:true, message:"none"};
              }
            break;
            case 1.5:
              if(randomNum <= 2){
                await roleWin(user.id, body.coin, body.coef)
                return {success:true, message:"Win"};
              } else if(randomNum <= 5){
                await roleLose(user.id, body.coin)
                return {success:true, message:"lose"};
              } else{
                return {success:true, message:"none"};
              }
            break;
            case 2:
              if(randomNum <= 1){
                await roleWin(user.id, body.coin, body.coef)
                return {success:true, message:"Win"};
              } else if(randomNum <= 5){
                await roleLose(user.id, body.coin)
                return {success:true, message:"lose"};
              } else{
                return {success:true, message:"none"};
              }
            break;
            case 2.5:
              if(randomNum <= 2){
                await roleWin(user.id, body.coin, body.coef)
                return {success:true, message:"Win"};
              } else if(randomNum <= 8){
                await roleLose(user.id, body.coin)
                return {success:true, message:"lose"};
              } else{
                return {success:true, message:"none"};
              }
            break;
            case 3:
              if(randomNum <= 1){
                await roleWin(user.id, body.coin, body.coef)
                return {success:true, message:"Win"};
              } else if(randomNum <= 9){
                await roleLose(user.id, body.coin)
                return {success:true, message:"lose"};
              } else{
                return {success:true, message:"none"};
              }
            break;
            case 5:
              if(randomNum <= 0){
                await roleWin(user.id, body.coin, body.coef)
                return {success:true, message:"Win"};
              } else if(randomNum <= 9){
                await roleLose(user.id, body.coin)
                return {success:true, message:"lose"};
              } else{
                return {success:true, message:"none"};
              }
            break;
            default:
              return {success:true, message:"Коэфицент не выбран"};
            break;
          }
        }
        else{
          return {success:true, message:"Недостаточно монет"};
        }
      } catch (err) {
        console.error("Ошибка при получении данных пользователя:", err);
        return { message: "Не удалось получить данные пользователя." };
      }
    }

    async cardUpgrade(card, user): Promise<any> {
      try {
        const { data } = await db.get('users', user.id);
        console.log(card)
        if(data.upgrades[0][card as keyof typeof data]){
          if(["cpu", "videocard", "proc"].includes(card)){
            if(data.coin >= data.upgrades[0][card as keyof typeof data][2]){
              data.coin -= data.upgrades[0][card as keyof typeof data][2] 
              data.energy.maxEnergy = data.energy.maxEnergy + data.upgrades[0][card as keyof typeof data][1] - data.upgrades[0][card as keyof typeof data][0] 
              data.upgrades[0][card as keyof typeof data][0] = data.upgrades[0][card as keyof typeof data][1]
              data.upgrades[0][card as keyof typeof data][1] = Math.ceil(data.upgrades[0][card as keyof typeof data][1] * upgradeCoef[card][0])
              data.upgrades[0][card as keyof typeof data][2] = Math.ceil(data.upgrades[0][card as keyof typeof data][2] * upgradeCoef[card][1])
            }
          } else{
            if (data.coin >= data.upgrades[0][card as keyof typeof data][2]){
              data.coin -= data.upgrades[0][card as keyof typeof data][2]
              data.energy.energyGeneric = data.energy.energyGeneric + data.upgrades[0][card as keyof typeof data][1] - data.upgrades[0][card as keyof typeof data][0] 
              data.upgrades[0][card as keyof typeof data][0] = data.upgrades[0][card as keyof typeof data][1]
              data.upgrades[0][card as keyof typeof data][1] = Math.ceil(data.upgrades[0][card as keyof typeof data][1] * upgradeCoef[card][0])
              data.upgrades[0][card as keyof typeof data][2] = Math.ceil(data.upgrades[0][card as keyof typeof data][2] * upgradeCoef[card][1])
            }
          }
        } else if(data.upgrades[1][card as keyof typeof data]){
          if(data.coin >= data.upgrades[1][card as keyof typeof data][2]){
            data.coin -= data.upgrades[1][card as keyof typeof data][2]
            data.click = data.click + data.upgrades[1][card as keyof typeof data][1] - data.upgrades[1][card as keyof typeof data][0] 
            data.upgrades[1][card as keyof typeof data][0] = data.upgrades[1][card as keyof typeof data][1]
            data.upgrades[1][card as keyof typeof data][1] = Math.ceil(data.upgrades[1][card as keyof typeof data][1] * upgradeCoef[card][0])
            data.upgrades[1][card as keyof typeof data][2] = Math.ceil(data.upgrades[1][card as keyof typeof data][2] * upgradeCoef[card][1])
          }
        }else if(data.upgrades[2][card as keyof typeof data]){
          if (data.coin >= data.upgrades[2][card as keyof typeof data][2]){
            data.coin -= data.upgrades[2][card as keyof typeof data][2]
            data.passive = data.passive + data.upgrades[2][card as keyof typeof data][1] - data.upgrades[2][card as keyof typeof data][0] 
            data.upgrades[2][card as keyof typeof data][0] = data.upgrades[2][card as keyof typeof data][1]
            data.upgrades[2][card as keyof typeof data][1] = Math.ceil(data.upgrades[2][card as keyof typeof data][1] * upgradeCoef[card][0])
            data.upgrades[2][card as keyof typeof data][2] = Math.ceil(data.upgrades[2][card as keyof typeof data][2] * upgradeCoef[card][1])
          }
        }else{
          return { message: "Не удалось обновить карточку." };
        }
        await db.update("users", data)
        return {success:true};
      } catch (err) {
        console.error("Ошибка при обновлении карточуи:", err);
        return { message: "Не удалось обновить карточку." };
      }
    }

    async getUserEarn(user): Promise<any>{
      try {
        const { data } = await db.get('users', '_design/users/_view/earn', { key: user.id });
        return {success:true, data}
      } catch (error) {
        return {message: "Не удалось получить данные"}
      }
    }

    async autch(body): Promise<any>{
      const { data } = await db.get('users', '_design/users/_view/autch', { key:`${body.username}` });
      if(data.rows.length){
        if(data.rows[0].value.password == createHash("sha256").update(body.password).digest("hex") ){
          const token = this.jwtService.sign(
            { id: data.rows[0].value._id }
          );
          return {"token":token, success: true}
        } else{
          return {"message":"Не верный пароль"}  
        }
      } else{
        return {"message":"Пользователь не найден"}
      }
    }
    async getAllUsers(): Promise<any>{
      const { data } = await db.get('users', '_design/users/_view/getAllUsers');
      return data
    }
    async getInviter(inviter): Promise<any>{
      try {
        const { data } = await db.get('users', '_design/users/_view/inviter', { key: inviter });
        return { success: true, data }
      } catch (error) {
        
      }
    }
    async reg(body): Promise<any> {
      let coin: number = 1000
      let inviterId: string = ''
      if(body.pass != body.repass){
        return {message: "Пароли должны совпадать."}
      }
      try {
        const { data } = await db.get('users', '_design/users/_view/autch', { key:`${body.login}` });
        if (data.rows.length)
          return {message: "Пользователь уже существует."}
      } catch (error) {
        
      }
      try {
        if(body.invitecode != ''){
          const { data } = await db.get('users', '_design/users/_view/inviter', { key: body.invitecode });
          if (!data.rows.length){
            return {message: "Не верный код приглашения."} 
          }else {
            coin += 5000
            inviterId = data.rows[0].id
          }
          }
      } catch (error) {
        
      }
      const data = {
        "login": body.login,
        "password": createHash("sha256").update(body.pass).digest("hex"),
        "info": body.userinfo,
        "invitecode": createHash("sha256").update(body.login).digest("hex"),
        "inviter": body.invitecode,
        "level": 1,
        "coin": coin,
        "energy": {
          "energy": 1000,
          "energyGeneric": 5,
          "maxEnergy": 1000
        },
        "click": 1,
        "passive": 0,
        "time": 0,
        "upgrades": [
          {
            "mouse": [
              0,
              1,
              100
            ],
            "keyboard": [
              0,
              3,
              200
            ],
            "monitor": [
              0,
              3,
              200
            ],
            "kreslo": [
              0,
              2,
              150
            ],
            "cpu": [
              0,
              200,
              450
            ],
            "videocard": [
              0,
              200,
              450
            ],
            "proc": [
              0,
              300,
              500
            ]
          },
          {
            "hydra": [
              0,
              1,
              100
            ],
            "burp": [
              0,
              1,
              200
            ],
            "sqlmap": [
              0,
              1,
              150
            ],
            "wireshark": [
              0,
              1,
              100
            ],
            "nmap": [
              0,
              1,
              150
            ],
            "hashcat": [
              0,
              1,
              150
            ],
            "nicto": [
              0,
              1,
              150
            ],
            "metasploit": [
              0,
              1,
              150
            ],
            "radare2": [
              0,
              1,
              200
            ],
            "netcat": [
              0,
              1,
              100
            ]
          },
          {
            "mainer": [
              0,
              5,
              2500
            ],
            "scam": [
              0,
              3,
              1500
            ],
            "darknet": [
              0,
              5,
              3000
            ],
            "fisching": [
              0,
              1,
              1000
            ],
            "reket": [
              0,
              2,
              1000
            ],
            "backdoor": [
              0,
              2,
              1500
            ],
            "carding": [
              0,
              4,
              2000
            ]
          }
        ]
      }
      try {
        await db.insert('users', data)
        if(inviterId != ''){
          await putCoin(inviterId, 1000)
        }
        return {success: true, message: "Привет, нам предстоит пройти сложный путь к становлению настоящим хакером. Надеюсь ты поможешь мне, и мы покажем этому миру кто тут главный! Самое время авторизоваться и начать зарабатывать!"}
      } catch (error) {
        console.log(error)
        return {message: "Не удалось зарегистрировать пользователя."}
      }
    }
}


async function putCoin(id: string, coin:number) {
  try {
    const { data } = await db.get('users', id)
    data.coin += coin
    console.log(data)
    await db.update('users', data)
  } catch (error) {
    putCoin(id,coin)
  }
}
async function roleWin(id:string, coin:number, coef:number) {
  try {
    const { data } = await db.get('users', id)
    data.coin += coin*coef
    await db.update('users', data)
  } catch (error) {
    roleWin(id, coin, coef)
  }
}
async function roleLose(id:string, coin:number) {
  try {
    const { data } = await db.get('users', id)
    data.coin -= coin
    await db.update('users', data)
  } catch (error) {
    roleLose(id, coin, )
  }
}
