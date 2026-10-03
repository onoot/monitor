import { Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
const NodeCouchDb = require('node-couchdb');

const db = new NodeCouchDb({
    host: 'db',
    protocol: 'http',
    port: 5984,
    auth: {
        user: 'admin',
        pass: 'admin'
    }
  });

@Injectable()
export class AutchService {
  constructor(private readonly jwtService: JwtService) {}
  async canActivateSocket(autch): Promise<string | null> {
    try {
      const token = autch;
      const decoded: any = this.jwtService.verify(token);
      const { data } = await db.get('users', '_design/users/_view/earn', { key:decoded.id });
      if (data){
        return decoded.id;
      }
      else{
        console.log('Данные от сервера не получены')
        return null
      }
    } catch (error) {
      console.log(`Ошибка получения данных: ${error}`)
      return null
    }
  }
}
