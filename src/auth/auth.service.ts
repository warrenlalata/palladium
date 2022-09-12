import { Body, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon2 from 'argon2';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService
  ) { }

  async signUpLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
      }
    });
    const tokens = await this.getTokens(newUser.id, newUser.email)
    await this.updateRefreshTokenHash(newUser.id, tokens.refresh_token)

    return tokens;
  }

  signInLocal() { }
  logout() { }
  refreshToken() { }

  async updateRefreshTokenHash(userId: number, refreshToken: string) {
    const hash = await this.hashData(refreshToken);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash
      },
    });
  }

  hashData(data: string) {
    return argon2.hash(data);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync({
        sub: userId,
        email
      }, {
        secret: 'access-token-secret',
        expiresIn: 60 * 15 // 15 minutes
      }),
      this.jwtService.signAsync({
        sub: userId,
        email
      }, {
        secret: 'refresh-token-secret',
        expiresIn: 60 * 60 * 24 * 7
      })
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken
    };
  }
}
