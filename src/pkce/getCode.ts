import { InvalidRequestError, Request } from 'oauth2-server';
import { TYPE } from './index';

export const getCodeChallenge = function (request: Request) {
  const codeChallenge =
    request.body.code_challenge ?? request.query?.code_challenge;

  if (!codeChallenge) {
    return null;
  }

  // https://tools.ietf.org/html/rfc7636#section-4
  if (!codeChallenge.match(/^([A-Za-z0-9\.\-\_\~]){43,128}$/)) {
    throw new InvalidRequestError('Invalid parameter: `code_challenge`');
  }

  return codeChallenge;
};

export const getCodeChallengeMethod = function (request: Request) {
  const codeChallengeMethod =
    request.body.code_challenge_method ?? request.query?.code_challenge_method;

  // https://tools.ietf.org/html/rfc7636#section-4
  // Section 4.3 - codeChallengeMethod is optional.
  if (!codeChallengeMethod) {
    return null;
  }

  if (!Object.values(TYPE).includes(codeChallengeMethod)) {
    throw new InvalidRequestError('Invalid parameter: `code_challenge_method`');
  }

  return codeChallengeMethod;
};
