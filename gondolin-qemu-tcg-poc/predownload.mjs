/**
 * Downloads the Gondolin guest image to the default cache directory.
 * Run during Docker build so the container starts without needing network access.
 *
 * Usage: NODE_EXTRA_CA_CERTS=/path/to/ca.pem node predownload.mjs
 */
import { ensureGuestAssets, getAssetDirectory, getAssetVersion } from
  "@earendil-works/gondolin";

process.stderr.write(`[predownload] Gondolin guest ${getAssetVersion()} → ${getAssetDirectory()}\n`);
await ensureGuestAssets();
process.stderr.write("[predownload] Done.\n");
