// Writes the plugin's version beside the Functions at deploy, so the User-Agent they
// send the site carries it like every other client in the suite. See fellowship.ts.
const { readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const plugin = readFileSync(join(__dirname, '..', '..', '..', 'fellowship.php'), 'utf8');
const match = plugin.match(/^\s*\*\s*Version:\s*([0-9A-Za-z.+-]+)\s*$/m);

if (match === null) {
  throw new Error('No "Version:" line in fellowship.php.');
}

writeFileSync(join(__dirname, '..', 'version.txt'), `${match[1]}\n`);
console.log(`Functions stamped with version ${match[1]}`);
