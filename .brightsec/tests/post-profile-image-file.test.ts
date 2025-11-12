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

test('POST /profile/image/file', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'csrf', 'stored_xss', 'osi', 'ssrf'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/profile/image/file`,
      headers: {
        'Cookie': 'token=valid-authentication-token',
        'Content-Type': 'multipart/form-data'
      },
      body: "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"validProfileImage.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<binary data>\r\n--boundary--",
      auth: process.env.BRIGHT_AUTH_ID
    });
});