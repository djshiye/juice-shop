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

test('PUT /api/security-answers/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'sqli', 'xss', 'csrf', 'jwt'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/SecurityAnswers/1`,
      body: { answer: 'Blurp' },
      headers: { Authorization: 'Bearer <token>' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});