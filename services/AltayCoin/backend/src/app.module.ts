import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { GameGateway } from './game/game.gateway';
import { AutchGuard } from './users/autch.guard';
import { AutchService } from './game/autch.service';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
      JwtModule.register({
        secret: 'asfdsfqwqwcwd21e3duis',
      }),
      UsersModule],
  providers: [GameGateway, AutchGuard, AutchService],
})
export class AppModule {}
