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

test('POST /rest/basket/1/checkout', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['test/api/basketApiSpec.ts', 'test/cypress/e2e/basket.spec.ts'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] },
      skipStaticParams: false
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/rest/basket/1/checkout`,
      body: {
        orderDetails: {
          deliveryMethodId: 1,
          paymentId: 'wallet'
        },
        UserId: 1
      },
      headers: {
        Authorization: 'Bearer <token>',
        'Content-Type': 'application/json'
      }
    });
});