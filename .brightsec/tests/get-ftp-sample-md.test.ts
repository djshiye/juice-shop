import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /ftp/sample.md', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['directoryListingChallenge', 'accessLogDisclosureChallenge', 'xss', 'ssrf', 'lfi'],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/ftp/sample.md`,
      headers: { 'X-Recruiting': 'We are hiring! Check out our careers page.' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});