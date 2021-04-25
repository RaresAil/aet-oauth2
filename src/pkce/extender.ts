import { AuthorizationCode as AC, Request, Response } from 'oauth2-server';

import {
  validateAuthCode,
  getClient,
  handleAuthorization,
  saveAuthorizationCode
} from '.';
import { isPKCERequest } from './utils';

const AuthorizationCodeGrantType = require('oauth2-server/lib/grant-types/authorization-code-grant-type.js');
const AuthorizeHandler = require('oauth2-server/lib/handlers/authorize-handler.js');
const TokenHandler = require('oauth2-server/lib/handlers/token-handler.js');
const auth = require('basic-auth');

export interface AuthorizationCode extends AC {
  codeChallenge?: string;
  codeChallengeMethod?: 'S256' | 'plain';
}

const _getAuthorizationCode =
  AuthorizationCodeGrantType.prototype.getAuthorizationCode;
const _getClientCredentials = TokenHandler.prototype.getClientCredentials;

AuthorizationCodeGrantType.prototype.getAuthorizationCode = async function (
  request: Request,
  client: any
) {
  const code: AuthorizationCode = await _getAuthorizationCode.call(
    this,
    request,
    client
  );

  validateAuthCode(request, code);
  return code;
};

TokenHandler.prototype.getClientCredentials = function (request: Request) {
  const credentials = auth(request);
  const grantType = request.body.grant_type;

  if (
    !credentials &&
    !request.body.client_secret &&
    isPKCERequest(request, grantType) &&
    request.body.client_id
  ) {
    return { clientId: request.body.client_id };
  }

  return _getClientCredentials.call(this, request);
};

TokenHandler.prototype.getClient = function (
  request: Request,
  response: Response
) {
  return getClient(this, request, response);
};

AuthorizeHandler.prototype.handle = function (
  request: Request,
  response: Response
) {
  return handleAuthorization(this, request, response);
};

AuthorizeHandler.prototype.saveAuthorizationCode = function (
  authorizationCode: any,
  expiresAt: any,
  scope: any,
  client: any,
  redirectUri: any,
  user: any,
  codeChallenge: any,
  codeChallengeMethod: any
) {
  return saveAuthorizationCode(
    this,
    authorizationCode,
    expiresAt,
    scope,
    client,
    redirectUri,
    user,
    codeChallenge,
    codeChallengeMethod
  );
};

/**
 * @typedef {Object} AuthorizationCode
 * This interface extends the Oauth2's AuthorizationCode and is adding the
 * PKCE support for the Oauth2 server
 * @memberof module:PKCE
 *
 * @property {string=} codeChallenge
 * @property {('S256' | 'plain')=} codeChallengeMethod
 */
