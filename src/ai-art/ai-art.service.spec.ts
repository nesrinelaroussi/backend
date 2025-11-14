import { Test, TestingModule } from '@nestjs/testing';
import { AiArtService } from './ai-art.service';

describe('AiArtService', () => {
  let service: AiArtService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AiArtService],
    }).compile();

    service = module.get<AiArtService>(AiArtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
