import { Config } from '@remotion/cli/config';

Config.setEntryPoint('src/index.ts');
Config.setVideoImageFormat('png');
Config.setOverwriteOutput(true);
/**
 * The film is composited with heavy backdrop-filter and layered transforms.
 * The GL angle backend below is the one that renders those consistently in the
 * headless shell; software rendering produces different blur radii.
 */
Config.setChromiumOpenGlRenderer('angle');
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
