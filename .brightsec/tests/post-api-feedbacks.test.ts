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

test('POST /api/feedbacks', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['stored_xss', 'bopla', 'sqli', 'csrf', 'business_constraint_bypass'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['SQLite'] },
      skipStaticParams: false
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Feedbacks`,
      body: {
        UserId: 1,
        comment: 'Great service!',
        rating: 5
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});