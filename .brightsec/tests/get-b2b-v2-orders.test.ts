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

test('GET /b2b/v2/orders', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['osi', 'sqli', 'ssrf', 'xss', 'csrf'],
      attackParamLocations: [AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/b2b/v2/orders`,
      headers: { 'X-Recruiting': 'your-recruitment-info' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});