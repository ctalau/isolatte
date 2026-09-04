# Audio

## Layers

Six independent layers, each with its own gain in `src/audio/manifest.ts`, so
the mix can be balanced without re-cutting anything.

| Layer | Gain | Ducked under voice | Status |
|---|---|---|---|
| voice | 1.00 | — | **generated** |
| music | 0.34 | ×0.55 | placeholder |
| ambience | 0.22 | ×0.70 | placeholder |
| ui | 0.50 | ×0.85 | placeholder |
| transition | 0.42 | ×0.80 | placeholder |
| impact | 0.60 | ×0.90 | placeholder |

Only the voice layer is enabled by default (`FilmAudio` props `enableMusic` and
`enableSfx` are `false`). Missing files would fail a render, and the picture is
designed to read without them.

## Narration — Kokoro

```
narration.json  →  Kokoro (ONNX, local)  →  per-scene WAV  →  peak-normalise
              →  measured duration  →  scene timing  →  Remotion timeline
```

`scripts/voice/generate.mjs`. One file per scene, not one long file, so a single
line can be re-voiced without regenerating the film and so scene durations can
be derived from measured audio length.

```bash
npm run voice                          # all scenes
npm run voice -- fusion reuse          # only those
KOKORO_VOICE=am_michael npm run voice  # different voice
KOKORO_SPEED=0.95 npm run voice        # slower read
```

Outputs `public/audio/voice/<scene>.wav`, `public/audio/voice/manifest.json`
(with measured durations) and a generated `src/film/voiceManifest.ts` the film
imports.

### Delivery direction

Intelligent, composed, confident, warm but restrained. Not a "YouTube voice",
not a trailer voice, not a radio read. Deliberate pacing with space around the
product claims.

Pacing is carried by the **handles** (`voiceLeadInFrames = 14`,
`voiceLeadOutFrames = 20`) rather than by slowing the read — a slowed read
sounds sluggish, silence around a claim sounds considered.

Current voice (`af_heart`) is a first pass and expected to change. Changing it
is one environment variable plus a regenerate; the film re-times itself.

## Sound design brief

Nine cues, all currently placeholders, specified in `src/audio/manifest.ts`.
The rule for all of them: **effects support movement, they do not announce it.**
If a viewer notices an individual sound effect, it is too loud or too bright.

* `ui.click` — short, dry, no pitch tail. Not a game UI.
* `ui.confirm` — soft two-note confirmation, barely above the bed.
* `whoosh.soft` — air movement, no pitch sweep. Supports the camera, not the cut.
* `transition.pass` — object passing the lens, stereo movement left→right.
* `merge.content` — two elements becoming one; short, granular, no reverb tail.
* `data.move` — fine-grained movement texture for distribution shots.
* `impact.low` — sub-heavy, no click. Used at most three times in the film.
* `riser.low` — tonal, ~2s, resolves rather than peaks.
* `ambience.room` — neutral air, gives the black frames a sense of space.

## Music

To be commissioned, not licensed from a library. Sophisticated electronic,
minimal pulse, restrained, modern, optimistic without becoming
inspirational-corporate. It must work under narration and resolve at the end
frame rather than fade.

Drop the file at `public/audio/music/bed.wav` and pass `music: true` to the
composition.
