import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  OnGatewayConnection,
  OnGatewayDisconnect
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { AutchService } from './autch.service';
const NodeCouchDb = require('node-couchdb');

const intervals: Record<string,NodeJS.Timeout> = {}
const ids: Record<string,string> = {}

const db = new NodeCouchDb({
  host: 'db',
  protocol: 'http',
  port: 5984,
  auth: {
      user: 'admin',
      pass: 'admin'
  }
});

async function Click(user, server): Promise<any>{
  try {
    const { data } = await db.get('users', user);
    if(Math.floor(data.energy.energy / 50) >= data.click){
      data.energy.energy -= data.click * 50
      data.coin += data.click
    }
    else if (data.energy.energy > 49){
      data.coin += Math.floor(data.energy.energy / 50)
      data.energy.energy -= Math.floor(data.energy.energy / 50) * 50
    }
    await db.update('users', data)
    server.to(`${user}`).emit('coinUpdate', data.coin)
    return data 
  } catch (error) {
    Click(user, server)
  }
}
async function energyRegen(user): Promise<any>{
  try {
    const { data } = await db.get('users', user);
    return data
  } catch (error) {
    console.log(error)
  }
}

@WebSocketGateway({ cors: true })
export class GameGateway implements OnGatewayConnection, OnGatewayDisconnect {
  constructor(
    private readonly autchService: AutchService,
  ) {}
  @WebSocketServer()
  server: Server;

  // 📌 При подключении
  handleConnection(client: Socket) {
    console.log(`🔌 Клиент подключился: ${client.id}`);
  }

  // 📌 При отключении
  async handleDisconnect(client: Socket) {
    console.log(`❌ Клиент отключился: ${client.id}`);
    if(intervals[`${client.id}`]){
      try {
        const date: Date = new Date
        const { data } = await db.get('users', ids[`${client.id}`])
        data.time = date.getHours()*3600 + date.getMinutes()*60 + date.getSeconds()
        await db.update('users', data)
      } catch (error) {
        console.log(error)
      }
      clearInterval(intervals[`${client.id}`])
      delete intervals[`${client.id}`]
      delete ids[`${client.id}`]
    }
  }

  @SubscribeMessage('click')
  async handleClick(@ConnectedSocket() client: Socket,  @MessageBody() data: any) {
    const userId = await this.autchService.canActivateSocket(data.Authorization);
    client.emit('clickUpdate', await Click(userId, this.server));
  }
  @SubscribeMessage('putEnergy')
  async getEnergy(@ConnectedSocket() client: Socket,  @MessageBody() data: any) {
    const userId = await this.autchService.canActivateSocket(data.Authorization);
    client.emit('putEnergy', await energyRegen(userId));
  }
  @SubscribeMessage('joinRoom')
  async joinRoom(@ConnectedSocket() client: Socket,  @MessageBody() data: any) {
    const userId = await this.autchService.canActivateSocket(data.Authorization);
    const date: Date = new Date
    const data1 = await db.get('users', userId)
    data1.data.coin += (date.getHours()*3600+date.getMinutes()*60+date.getSeconds() - data1.data.time) * data1.data.passive
    client.emit('putCoins', (date.getHours()*3600+date.getMinutes()*60+date.getSeconds() - data1.data.time) * data1.data.passive)
    await db.update("users", data1.data)
    client.join(`${userId}`);
    ids[`${client.id}`] = `${userId}`
    intervals[`${client.id}`] = setInterval(async ()=>{
      try {
        await updateDB(userId, this.server)
      } catch (error) {
        console.log(error)
      }
    }, 1000)
  }
}

async function updateDB(userId, server){
  try {
    const id = userId
    const { data } = await db.get('users', id)
    data.coin += data.passive
    if(data.level == 1 && data.coin>50000){
      data.level += 1
    } else if(data.level == 2 && data.coin>100000){
      data.level += 1
    } else if(data.level == 3 && data.coin>200000){
      data.level += 1
    } else if(data.level == 4 && data.coin>500000){
      data.level += 1
    }
    data.energy.energy = Math.min(data.energy.energy + data.energy.energyGeneric, data.energy.maxEnergy)
    await db.update('users', data)
    server.to(`${userId}`).emit('levelUpdate', data.level)
    server.to(`${userId}`).emit('coinUpdate', data.coin)
  } catch (error) {
    console.log(error)
  }
}