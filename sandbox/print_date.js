const fs = require('fs');

const now = new Date();
const output = `Current date: ${now.toISOString()}\n`;

fs.writeFileSync('/output/date.txt', output);
process.stdout.write(output);
