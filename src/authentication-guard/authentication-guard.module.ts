import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthenticationGuard } from './authentication-guard.guard';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET, // Add this to your .env
    }),
  ],
  providers: [AuthenticationGuard],
  exports: [AuthenticationGuard, JwtModule],
})
export class AuthModule {}
