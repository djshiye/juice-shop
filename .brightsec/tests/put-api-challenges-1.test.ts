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

test('PUT /api/challenges/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'csrf', 'sqli', 'xss'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/Challenges/1`,
      body: {
        name: 'New Challenge Name',
        category: 'New Category',
        description: 'Updated description for the challenge.',
        difficulty: 3,
        mitigationUrl: 'http://example.com/mitigation',
        solved: false,
        disabledEnv: 'production',
        tutorialOrder: 1,
        codingChallengeStatus: 0,
        hasCodingChallenge: true
      },
      headers: { 'Content-Type': 'application/json' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});