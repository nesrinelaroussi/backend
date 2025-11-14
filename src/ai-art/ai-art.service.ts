import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { GoogleGenerativeAI, GenerativeModel, GoogleGenerativeAIFetchError, GenerateContentResult } from '@google/generative-ai';
// Removed: import { ImageGenerationService } from './ImageGeneration.service';
import { jsonrepair } from 'jsonrepair';

const GEMINI_MODEL = 'gemini-2.0-flash-lite';

@Injectable()
export class AiArtService {
  private readonly googleAI: GoogleGenerativeAI;
  private readonly model: GenerativeModel;
  private readonly logger = new Logger(AiArtService.name);

  constructor(
    private readonly configService: ConfigService,
    // Removed: private readonly imageGenerationService: ImageGenerationService,
  ) {
    const geminiApiKey = this.configService.get<string>('GEMINI_API_KEY');
    if (!geminiApiKey) {
      throw new Error('GEMINI_API_KEY not found in environment variables.');
    }

    this.googleAI = new GoogleGenerativeAI(geminiApiKey);
    this.model = this.googleAI.getGenerativeModel({
      model: GEMINI_MODEL,
    });
  }

  private async callWithRetry<T>(
    apiCall: () => Promise<T>,
    maxRetries = 5,
    baseDelayMs = 1000
  ): Promise<T> {
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await apiCall();
      } catch (error) {
        if (error instanceof GoogleGenerativeAIFetchError && error.status === 429) {
          const delay = baseDelayMs * Math.pow(2, i);
          this.logger.warn(`Rate limit hit. Retrying in ${delay / 1000} seconds... (Attempt ${i + 1}/${maxRetries})`);
          await new Promise(resolve => setTimeout(resolve, delay));
        } else {
          throw error;
        }
      }
    }
    throw new Error(`Failed after ${maxRetries} retries due to persistent rate limiting.`);
  }

  async generateArtistsList(theme: string) {
    const prompt = `
You are an expert art curator.
Generate a list of 10 famous artists that fit the theme: "${theme}".
For each artist, include their full name, a detailed description of their art style, their country of origin, and a list of 3-5 of their most famous works (paintings/sculptures/etc.).

Return the result strictly in JSON with the following structure. DO NOT include any other text or formatting, just the JSON object. Ensure all strings are properly quoted and commas are correctly placed.

{
  "artists": [
    {
      "name": "string",
      "style_description": "string",
      "country": "string",
      "famous_works": [
        "string",
        "string",
        "string"
      ]
    }
  ]
}
    `;

    try {
      const result = await this.callWithRetry(async () => {
        return await this.model.generateContent(prompt);
      });

      let rawText = await result.response.text();

      rawText = rawText.replace(/^```json\s*/, '').replace(/```$/, '').trim();

      const jsonMatch = rawText.match(/\{[\s\S]*\}/);
      if (jsonMatch && jsonMatch[0]) {
        rawText = jsonMatch[0];
      } else {
        this.logger.error('No JSON object detected in AI response after initial cleaning. Raw text:', rawText);
        throw new Error('AI response did not contain a valid JSON object.');
      }

      let repairedJsonText = rawText;
      try {
        repairedJsonText = jsonrepair(rawText);
        this.logger.log('JSON successfully repaired.');
      } catch (repairError) {
        this.logger.error('Failed to repair JSON. Original raw text:', rawText, 'Repair error:', repairError);
        throw new Error('AI response JSON could not be repaired.');
      }

      const artistsJson = JSON.parse(repairedJsonText);
      // Now, simply return the artists without any image generation
      return { artists: artistsJson.artists }; // Direct return of the artists array

    } catch (error) {
      this.logger.error('Failed to generate or parse artists list:', error); // Updated log message
      if (error instanceof SyntaxError || error.message.includes('AI response did not contain a valid JSON object') || error.message.includes('AI response JSON could not be repaired')) {
          throw new Error('AI response was not valid JSON. Please try again or refine the prompt.');
      }
      if (error.message.includes('persistent rate limiting')) {
          throw new Error('AI artist generation failed due to persistent rate limits. Please try again later.');
      }
      throw new Error('AI artist generation failed');
    }
  }
}