#!/usr/bin/env bun
import { Verifier } from '@tinfoilsh/verifier';
import fs from 'node:fs';

const path = process.argv[2];
const outPath = process.argv[3];
if (!path) { console.error('usage: verify_tinfoil.mjs <attestation.json> [out.json]'); process.exit(2); }
const raw = JSON.parse(fs.readFileSync(path, 'utf8'));
const bundle = raw.bundle ?? raw.evidence?.bundle ?? raw;
if (!bundle?.enclaveAttestationReport) { console.error('no bundle.enclaveAttestationReport in', path); process.exit(2); }

const startedAt = new Date().toISOString();
const verifier = new Verifier({ configRepo: 'tinfoilsh/confidential-model-router' });
const result = await verifier.verifyBundle(bundle);
const doc = verifier.getVerificationDocument();
const output = {
  source: path,
  startedAt,
  finishedAt: new Date().toISOString(),
  verified: true,
  result,
  document: doc,
};
if (outPath) fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
console.log(JSON.stringify(output, null, 2));
