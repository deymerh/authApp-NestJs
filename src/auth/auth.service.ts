import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response.interface';
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';

const ERROR_USER_ALREADY_EXIST = 11000;

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) { }

  async create(createAuthDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...newUserData } = createAuthDto;
      const newUser = new this.userModel({ password: bcryptjs.hashSync(password, 10), ...newUserData });
      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if (error.code === ERROR_USER_ALREADY_EXIST) {
        throw new BadRequestException(`${createAuthDto.email} already exist!`);
      }
      throw new InternalServerErrorException('Something terribe happen!!')
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Not valid credencialts - email');
    }
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credencialts - password');
    }
    const { password: _, ...rest } = user.toJSON();
    return {
      user: rest,
      token: this.getJwtToken({ id: user.id })
    };
  }

  async register(registerDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerDto);
    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(userId: string) {
    const user = await this.userModel.findById(userId);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

}
