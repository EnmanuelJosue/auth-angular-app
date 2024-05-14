import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';

import { Model } from 'mongoose';

import * as bryptjs from 'bcryptjs';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register-user.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,

    private jwtService: JwtService
  ){

  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        ...userData,
        password: bryptjs.hashSync(password, 10)
      });
      await newUser.save();
     
      return newUser.toJSON();

    } catch (error) {
      console.log(error.code);
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists`);
      }
      throw new InternalServerErrorException('Something internal happen');
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse>{
    const user = await this.create(registerUserDto);
    delete user.password;
    return {
      user,
      token: await this.getJwt({ id: user._id })
    };
  }

  async login(loginDto: LoginDto): Promise<LoginResponse>{

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) throw new UnauthorizedException('Not valid credentials');
    
    if ( !bryptjs.compareSync(password, user.password )) {
      throw new UnauthorizedException('Not valid credentials');
    }

    const resp = user.toJSON();
    delete resp.password;

    return {
      user: resp,
      token: await this.getJwt({ id: user.id })
    };
  }

  async findAll(): Promise<User[]> {
    return await this.userModel.find();
  }

  async findOne(id: string): Promise<User> {
    const user =  (await this.userModel.findById(id)).toJSON();
    delete user.password;
    return user;
  }

  async checkToken(user: User): Promise<LoginResponse> {
    return {
      user: user,
      token: await this.getJwt({ id: user._id })
    };
  }

  // update(id: number, updateAuthDto: UpdateAuthDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }

  async getJwt(payload: JwtPayload){
    const token = await this.jwtService.signAsync( payload );
    return token;
  }
}
