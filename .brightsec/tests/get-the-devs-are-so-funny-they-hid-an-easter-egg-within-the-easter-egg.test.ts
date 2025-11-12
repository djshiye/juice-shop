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

test('GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['full_path_disclosure', 'xss', 'improper_asset_management'],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg`,
      headers: { 'X-Recruiting': '<recruiting_info_here>' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});