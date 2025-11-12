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

test('POST /rest/user/reset-password', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'email_injection', 'xss', 'sqli', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/rest/user/reset-password`,
      body: {
        email: 'user@example.com',
        answer: 'correct_answer',
        new: 'new_password',
        repeat: 'new_password'
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});