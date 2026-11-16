'use strict'

const fs = require('node:fs')
const path = require('node:path')
const dotenv = require('dotenv')
const identity = require('./node_modules/dotenv/package.json')
const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors.json'), 'utf8'))

if (identity.version !== '18.0.9') throw new Error('consumer identity differs')
let count = 0
for (const vector of [...vectors.emissions, ...vectors.parserCases]) {
  const parsed = dotenv.parse(Buffer.from(vector.encoded, 'utf8'))
  const names = Object.keys(vector.values).sort()
  const actualNames = Object.keys(parsed).sort()
  if (names.length !== actualNames.length || names.some((name, i) => name !== actualNames[i])) {
    throw new Error(`vector ${count}: key set differs`)
  }
  for (const name of names) {
    if (!Object.prototype.hasOwnProperty.call(parsed, name) || typeof parsed[name] !== 'string' ||
        !Buffer.from(parsed[name], 'utf8').equals(Buffer.from(vector.values[name], 'utf8'))) {
      throw new Error(`vector ${count}: value bytes differ`)
    }
  }
  count++
}
process.stdout.write(JSON.stringify({ node: process.version, dotenv: identity.version, vectors: count }) + '\n')
