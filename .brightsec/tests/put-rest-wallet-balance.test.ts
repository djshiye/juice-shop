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

test('PUT /rest/wallet/balance', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'nosql', 'csrf', 'business_constraint_bypass', 'xss'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/rest/wallet/balance`,
      body: {
        UserId: 123,
        paymentId: 456,
        balance: 100
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});