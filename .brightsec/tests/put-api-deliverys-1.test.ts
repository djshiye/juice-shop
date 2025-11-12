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

test('PUT /api/deliverys/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'sqli', 'xss', 'csrf', 'file_upload'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/deliverys/1`,
      body: {
        name: 'Express Delivery',
        price: 5.99,
        deluxePrice: 9.99,
        eta: 2,
        icon: 'express-icon.png'
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});