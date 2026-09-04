/** Minimal 16-bit PCM mono WAV writer. No dependency, fully deterministic. */
export const encodeWav = (samples, sampleRate) => {
  const bytesPerSample = 2;
  const dataSize = samples.length * bytesPerSample;
  const buffer = Buffer.alloc(44 + dataSize);

  buffer.write('RIFF', 0);
  buffer.writeUInt32LE(36 + dataSize, 4);
  buffer.write('WAVE', 8);
  buffer.write('fmt ', 12);
  buffer.writeUInt32LE(16, 16); // PCM chunk size
  buffer.writeUInt16LE(1, 20); // format = PCM
  buffer.writeUInt16LE(1, 22); // channels
  buffer.writeUInt32LE(sampleRate, 24);
  buffer.writeUInt32LE(sampleRate * bytesPerSample, 28);
  buffer.writeUInt16LE(bytesPerSample, 32);
  buffer.writeUInt16LE(16, 34);
  buffer.write('data', 36);

  for (let i = 0; i < samples.length; i++) {
    const s = Math.max(-1, Math.min(1, samples[i]));
    buffer.writeInt16LE(Math.round(s * 32767), 44 + i * bytesPerSample);
  }
  return buffer;
};

/** Peak-normalise to `target`, then append `tailSeconds` of digital silence. */
export const normalizeAndPad = (samples, target, tailSeconds, sampleRate) => {
  let peak = 0;
  for (const s of samples) peak = Math.max(peak, Math.abs(s));
  const gain = peak > 1e-6 ? target / peak : 1;

  const tail = Math.round(tailSeconds * sampleRate);
  const out = new Float32Array(samples.length + tail);
  for (let i = 0; i < samples.length; i++) out[i] = samples[i] * gain;
  return out;
};
