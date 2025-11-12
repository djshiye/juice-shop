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

test('GET /rest/user/authentication-details', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['test/api/authenticatedUsersSpec.ts'],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/rest/user/authentication-details?callback=<callback_function>` ,
      headers: { 'X-Recruiting': '<recruiting_info>' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});