import { Body, Controller, Get, Param, Post, Put, Query, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { AutchGuard } from './autch.guard';
import { Request } from 'express';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('check-token')
  @UseGuards(AutchGuard)
  checkToken(@Req() req) {
    return { success: true, user: req.user };
  }

  @Get('table')
  getTable(): string {
    return 'table';
  }

  @Get('info')
  @UseGuards(AutchGuard)
  getUserInfo(@Req() request: Request & { user?: any }): Promise<any> {
    return this.usersService.getUserInfo(request.user)
  }

  @Get('earn')
  @UseGuards(AutchGuard)
  getUserEarn(@Req() request: Request & { user?: any }): Promise<any> {
    return this.usersService.getUserEarn(request.user)
  }

  @Get('info/:id')
  @UseGuards(AutchGuard)
  getUserInfoId(@Param() params: any): Promise<any> {
    return this.usersService.getUserInfoId()
  }

  @Get('upgrades')
  @UseGuards(AutchGuard)
  getUserUpgrades(@Req() request: Request & { user?: any }): Promise<any> {
    return this.usersService.getUserUpgrades(request.user)
  }
  @Get('allusers')
  @UseGuards(AutchGuard)
  getAllUsers(@Req() request: Request & { user?: any }): Promise<any> {
    return this.usersService.getAllUsers()
  }
  @Get('inviter')
  @UseGuards(AutchGuard)
  getInviter(@Req() request: Request & { user?: any }, @Query('inviterCode') inviterCode:string): Promise<any> {
    return this.usersService.getInviter(inviterCode)
  }

  @Post('upgrade/:card')
  @UseGuards(AutchGuard)
  CaedUpgrade(@Param() params: any, @Req() request: Request & { user?: any }): Promise<any> {
    return this.usersService.cardUpgrade(params.card, request.user)
  }
  @Post('autch')
  autch(@Body() body: JSON): Promise<any> {
    return this.usersService.autch(body)
  }

  @Post('reg')
  reg(@Body() body: JSON): Promise<any> {
    return this.usersService.reg(body)
  }
  @Post('role')
  @UseGuards(AutchGuard)
  role(@Body() body: JSON, @Req() request: Request & { user?: any }): Promise<any> {
    return this.usersService.role(request.user, body)
  }
}