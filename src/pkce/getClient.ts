import {
  Client,
  InvalidClientError,
  InvalidRequestError,
  ServerError,
  Request,
  Response
} from 'oauth2-server';

import { isPKCERequest } from './utils';

const promisify = require('promisify-any').use(require('bluebird'));
const is = require('oauth2-server/lib/validator/is.js');

/* eslint-disable require-jsdoc */
export default function getClient(
  self: any,
  request: Request,
  response: Response
): any {
  const credentials = self.getClientCredentials(request);
  const grantType = request.body.grant_type;

  if (!credentials.clientId) {
    throw new InvalidRequestError('Missing parameter: `client_id`');
  }

  if (
    self.isClientAuthenticationRequired(grantType) &&
    !credentials.clientSecret &&
    !isPKCERequest(request, grantType)
  ) {
    throw new InvalidRequestError('Missing parameter: `client_secret`');
  }

  if (!is.vschar(credentials.clientId)) {
    throw new InvalidRequestError('Invalid parameter: `client_id`');
  }

  if (credentials.clientSecret && !is.vschar(credentials.clientSecret)) {
    throw new InvalidRequestError('Invalid parameter: `client_secret`');
  }

  return promisify(self.model.getClient, 2)
    .call(self.model, credentials.clientId, credentials.clientSecret)
    .then(function (client: Client) {
      if (!client) {
        throw new InvalidClientError('Invalid client: client is invalid');
      }

      if (!client.grants) {
        throw new ServerError('Server error: missing client `grants`');
      }

      if (!(client.grants instanceof Array)) {
        throw new ServerError('Server error: `grants` must be an array');
      }

      return client;
    })
    .catch(function (e: Error) {
      // Include the "WWW-Authenticate" response header field if the client
      // attempted to authenticate via the "Authorization" request header.
      //
      // @see https://tools.ietf.org/html/rfc6749#section-5.2.
      if (e instanceof InvalidClientError && request.get('authorization')) {
        response.set('WWW-Authenticate', 'Basic realm="Service"');

        throw new InvalidClientError(e, { code: 401 });
      }

      throw e;
    });
}
