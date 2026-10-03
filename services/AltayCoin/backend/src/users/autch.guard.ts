import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
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
export class AutchGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: any }>();
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedException('Токен отсутствует или имеет неверный формат');
    }

    try {
      const token = authHeader;
      const decoded: any = this.jwtService.verify(token); 
      const { data } = await db.get('users', '_design/users/_view/getInfo', { key:decoded.id });
      if (data){
        request.user = {id: decoded.id}
        return true;
      }
      else{
        throw new UnauthorizedException('Ошибка авторизации');
      }
    } catch (error) {
      throw new UnauthorizedException('Ошибка авторизации: ' + error.message);
    }
  }
}