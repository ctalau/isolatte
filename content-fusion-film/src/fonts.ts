import '@fontsource-variable/inter';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import { continueRender, delayRender } from 'remotion';

/**
 * Fonts ship with the project (no network at render time) but the browser still
 * needs a frame to parse them. Remotion must not capture a frame before that,
 * or the first frames render in a fallback face.
 */
const handle = delayRender('load-fonts');

if (typeof document !== 'undefined') {
  document.fonts.ready
    .then(() => continueRender(handle))
    .catch(() => continueRender(handle));
} else {
  continueRender(handle);
}
