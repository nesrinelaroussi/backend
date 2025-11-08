import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';



async function bootstrap() {
  console.log(process.env.MONGO_URL); 
  const app = await NestFactory.create(AppModule);
  dotenv.config();
 
  await app.listen(3000,'0.0.0.0');
} 
bootstrap();
