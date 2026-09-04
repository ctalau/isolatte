/**
 * Kokoro narration configuration.
 *
 * Voice ID is configurable because the final voice is a creative decision that
 * has not been made yet. The brief's direction — intelligent, composed, warm
 * but restrained, deliberate pacing, not a "YouTube voice" — maps to a lower,
 * slower delivery, which is what the defaults below aim at.
 */
export const voiceConfig = {
  /** kokoro-js voice id. Override with KOKORO_VOICE. */
  voiceId: process.env.KOKORO_VOICE ?? 'af_nicole',
  /** Model id on Hugging Face. Override with KOKORO_MODEL. */
  modelId: process.env.KOKORO_MODEL ?? 'onnx-community/Kokoro-82M-v1.0-ONNX',
  dtype: process.env.KOKORO_DTYPE ?? 'q8',
  /**
   * < 1 slows delivery. Pacing is carried by the *handles* around each line
   * (voiceLeadInFrames / voiceLeadOutFrames) rather than by slowing the read,
   * which keeps the delivery composed instead of sluggish.
   */
  speed: Number(process.env.KOKORO_SPEED ?? 1.0),
  sampleRate: 24000,
  outputDir: 'public/audio/voice',
  manifestFile: 'public/audio/voice/manifest.json',
  /** Generated TS module the film imports for scene timing. */
  tsManifest: 'src/film/voiceManifest.ts',
  /** Peak-normalisation target (linear) applied to every clip. */
  normalizePeak: 0.89,
};
