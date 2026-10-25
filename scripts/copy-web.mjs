// Copies the web app (index.html, security.js, the alert list and icons) into www/ for the Capacitor
// app, and adds the Capacitor runtime so the page can reach native plugins (push notifications).
// The root index.html stays a plain web page that also works in a browser.
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const OUT = 'www';
rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT + '/functions', { recursive: true });

for (const f of ['security.js', 'manifest.json', 'icon-192.png', 'icon-512.png', 'functions/alert-types.js']) {
  if (!existsSync(f)) throw new Error(f + ' is missing');
  cpSync(f, `${OUT}/${f}`);
}
cpSync('node_modules/@capacitor/core/dist/capacitor.js', `${OUT}/capacitor.js`);

const MARK = '<!-- capacitor runtime -->';
const html = readFileSync('index.html', 'utf8');
if (!html.includes(MARK)) throw new Error(`index.html is missing the "${MARK}" marker`);
writeFileSync(`${OUT}/index.html`, html.replace(MARK, '<script src="capacitor.js"></script>'));
console.log('Web app copied to www/');
