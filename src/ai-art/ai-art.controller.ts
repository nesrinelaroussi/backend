import { Controller, Get, Query } from '@nestjs/common';
import { AiArtService } from './ai-art.service';

@Controller('ai-art')
export class AiArtController {
  constructor(private readonly aiArtService: AiArtService) {}

  @Get('artists')
  async getArtists(@Query('theme') theme: string) {
    return this.aiArtService.generateArtistsList(theme || 'Modern Art');
  }
}
