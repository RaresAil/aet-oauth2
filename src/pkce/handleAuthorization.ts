import {
  AccessDeniedError,
  InvalidArgumentError,
  OAuthError,
  ServerError,
  Request,
  Response,
  InvalidRequestError
} from 'oauth2-server';
import { getCodeChallenge, getCodeChallengeMethod } from './index';

const Promise = require('bluebird');

/* eslint-disable require-jsdoc */
export default function handleAuthorization(
  self: any,
  request: any,
  response: any
): any {
  if (!(request instanceof Request)) {
    throw new InvalidArgumentError(
      'Invalid argument: `request` must be an instance of Request'
    );
  }

  if (!(response instanceof Response)) {
    throw new InvalidArgumentError(
      'Invalid argument: `response` must be an instance of Response'
    );
  }

  if ('false' === request.query?.allowed) {
    return Promise.reject(
      new AccessDeniedError('Access denied: user denied access to application')
    );
  }

  const fns = [
    self.getAuthorizationCodeLifetime(),
    self.getClient(request),
    self.getUser(request, response)
  ];

  return Promise.all(fns)
    .bind(self)
    .spread(function (expiresAt: any, client: any, user: any) {
      const uri = self.getRedirectUri(request, client);
      let scope: any;
      let state: any;
      let ResponseType: any;

      return Promise.bind(self)
        .then(function () {
          const requestedScope = self.getScope(request);
          return self.validateScope(user, client, requestedScope);
        })
        .then(function (validScope: any) {
          scope = validScope;
          return self.generateAuthorizationCode(client, user, scope);
        })
        .then(function (authorizationCode: any) {
          state = self.getState(request);
          ResponseType = self.getResponseType(request);

          const codeChallenge = getCodeChallenge(request);
          const codeChallengeMethod = getCodeChallengeMethod(request);

          if (!codeChallenge && codeChallengeMethod) {
            throw new InvalidRequestError(
              'Missing parameter: `code_challenge`'
            );
          }

          return self.saveAuthorizationCode(
            authorizationCode,
            expiresAt,
            scope,
            client,
            uri,
            user,
            codeChallenge,
            codeChallengeMethod
          );
        })
        .then(function (code: any) {
          const responseType = new ResponseType(code.authorizationCode);
          const redirectUri = self.buildSuccessRedirectUri(uri, responseType);
          self.updateResponse(response, redirectUri, state);
          return code;
        })
        .catch(function (e: Error) {
          if (!(e instanceof OAuthError)) {
            e = new ServerError(e);
          }
          const redirectUri = self.buildErrorRedirectUri(uri, e);

          self.updateResponse(response, redirectUri, state);
          throw e;
        });
    });
}
