import { TYPE } from './index';

const promisify = require('promisify-any').use(require('bluebird'));

/* eslint-disable require-jsdoc */
export default function saveAuthorizationCode(
  self: any,
  authorizationCode: any,
  expiresAt: any,
  scope: any,
  client: any,
  redirectUri: any,
  user: any,
  codeChallenge: any,
  codeChallengeMethod: any
) {
  const code: any = {
    authorizationCode: authorizationCode,
    expiresAt: expiresAt,
    redirectUri: redirectUri,
    scope: scope
  };

  if (codeChallenge) {
    code.codeChallenge = codeChallenge;
    code.codeChallengeMethod = codeChallengeMethod ?? TYPE.PLAIN;
  }

  return promisify(self.model.saveAuthorizationCode, 3).call(
    self.model,
    code,
    client,
    user
  );
}
