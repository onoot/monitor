import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { AutchGuard } from './autch.guard';
import { JwtModule } from '@nestjs/jwt';
import { GameGateway } from 'src/game/game.gateway';

@Module({
  imports: [
    JwtModule.register({
      secret: 'asfdsfqwqwcwd21e3duis',
    }),
  ],
  controllers: [UsersController],
  providers: [UsersService, AutchGuard],
})
export class UsersModule {}
