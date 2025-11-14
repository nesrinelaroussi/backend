import { Test, TestingModule } from '@nestjs/testing';
import { AiArtController } from './ai-art.controller';

describe('AiArtController', () => {
  let controller: AiArtController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AiArtController],
    }).compile();

    controller = module.get<AiArtController>(AiArtController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
