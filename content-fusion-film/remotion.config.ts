import { Config } from '@remotion/cli/config';

Config.setEntryPoint('src/index.ts');
Config.setVideoImageFormat('png');
Config.setOverwriteOutput(true);
/**
 * The film is composited with heavy backdrop-filter and layered transforms,
 * and scenes 09-10 render real WebGL (react-three-fiber). `swangle` (software
 * ANGLE) is the backend that actually creates a WebGL context in a headless,
 * GPU-less sandbox — plain `angle`/`egl` fail there with "Error creating WebGL
 * context" — while still rendering the CSS filters consistently, unlike
 * `swiftshader`.
 */
Config.setChromiumOpenGlRenderer('swangle');
Config.setConcurrency(2);
Config.setDelayRenderTimeoutInMilliseconds(60000);

/**
 * Use an already-present Chromium when one is available (CI images and this
 * dev container ship one), instead of downloading a second headless shell.
 */
const browser = process.env.REMOTION_BROWSER;
if (browser) {
  Config.setBrowserExecutable(browser);
}
