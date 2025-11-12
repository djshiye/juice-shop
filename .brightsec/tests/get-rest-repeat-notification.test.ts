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

test('GET /rest/repeat-notification', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'business_constraint_bypass', 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.QUERY],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/rest/repeat-notification?challenge=Score%20Board`,
      auth: process.env.BRIGHT_AUTH_ID
    });
});