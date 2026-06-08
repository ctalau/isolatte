// Fetches the Oxygen XML Editor home page and reports whether the request
// went through an HTTP(S) proxy. Proxy selection comes entirely from the
// HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables, handled by
// Node's built-in EnvHttpProxyAgent (enabled via the --use-env-proxy flag
// passed to `node` in run.sh — this script does not configure a proxy itself).

const URL_TO_FETCH = 'https://www.oxygenxml.com/';

console.log('HTTP_PROXY  =', process.env.HTTP_PROXY || process.env.http_proxy || '(unset)');
console.log('HTTPS_PROXY =', process.env.HTTPS_PROXY || process.env.https_proxy || '(unset)');
console.log('NO_PROXY    =', process.env.NO_PROXY || process.env.no_proxy || '(unset)');
console.log(`Fetching ${URL_TO_FETCH} ...`);

const res = await fetch(URL_TO_FETCH);
const body = await res.text();
const title = body.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim();

console.log('status        :', res.status, res.statusText);
console.log('content-length:', body.length, 'bytes');
console.log('page title    :', title ?? '(not found)');
