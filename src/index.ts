/** @module OAuthServer **/

export { AuthorizationCode, TYPE } from './pkce';

import OAuth2Server, {
  InvalidArgumentError,
  AuthenticateOptions,
  AuthorizeOptions,
  ServerOptions,
  TokenOptions,
  Response,
  Request
} from 'oauth2-server';
import {
  Response as ExpressResponse,
  Request as ExpressRequest,
  NextFunction
} from 'express';

export interface ContinueMiddleware {
  token?: boolean;
  authorize?: boolean;
}
export interface OAuthServerOptions extends ServerOptions {
  continueMiddleware?: ContinueMiddleware;
}

export interface ExpressMiddleware {
  (
    req: ExpressRequest,
    res: ExpressResponse,
    next: NextFunction
  ): Promise<void>;
}

export interface ErrorObject {
  status?: number;
  message?: string;
}

export interface CustomErrorResponse {
  (
    res: ExpressResponse,
    status: number,
    message: string,
    _error: ErrorObject
  ): void;
}

/**
 * @typedef {Function} ExpressMiddleware
 * @memberof module:OAuthServer
 *
 * @param {ExpressRequest} req The request object
 * @param {ExpressResponse} res The response object
 * @param {NextFunction} next The next function
 * The message of the error. (If the status is >= 500, the message will always be "Internal Server Error")
 * @return {Promise<void>}
 */
/**
 * @typedef {Object} ErrorObject
 * @memberof module:OAuthServer
 *
 * @property {number=} status The error's status code
 * @property {string=} message The error's message
 */
/**
 * @typedef {Function} CustomErrorResponse
 * @memberof module:OAuthServer
 *
 * @param {ExpressResponse} res The response object that you can use to send the response to the client.
 * @param {number} status The status of the error.
 * @param {string} message
 * The message of the error. (If the status is >= 500, the message will always be "Internal Server Error")
 * @param {module:OAuthServer.ErrorObject} _error
 * If the status is >= 500, you can use the error object to check the Server Error
 * @return {void}
 */
/**
 * @typedef {Object} ContinueMiddleware Specify which action should be sent to responder.
 * @memberof module:OAuthServer
 *
 * @property {boolean=} token If true, at the end the action will be sent to the responder. (Default: false)
 * @property {boolean=} authorize If true, at the end the action will be sent to the responder. (Default: false)
 */
/**
 * @typedef {Object} OAuthServerOptions This class extends the ServerOptions class.
 * @memberof module:OAuthServer
 *
 * @property {module:OAuthServer.ContinueMiddleware=} continueMiddleware
 * Specify which action should be sent to responder.
 * @property {ServerOptions.model} model The model for the oauth2server.
 * @property {number} accessTokenLifetime The expire time in seconds
 */
/**
 * @typedef {Object} AuthenticateOptions The OAuth2Server's AuthenticateOptions
 * @memberof module:OAuthServer
 *
 * @property {Array<string>=} scope
 * The scope(s) to authenticate.
 * @property {boolean=} addAcceptedScopesHeader
 * Set the X-Accepted-OAuth-Scopes HTTP header on response objects.
 * @property {boolean=} addAuthorizedScopesHeader
 * Set the X-OAuth-Scopes HTTP header on response objects.
 * @property {boolean=} allowBearerTokensInQueryString
 * Allow clients to pass bearer tokens in the query string of a request.
 */
/**
 * @typedef {Object} AuthorizeOptions The OAuth2Server's AuthorizeOptions
 * @memberof module:OAuthServer
 *
 * @property {{}=} authenticateHandler
 * The authenticate handler
 * @property {boolean=} allowEmptyState
 * Allow clients to specify an empty state
 * @property {number=} authorizationCodeLifetime
 * Lifetime of generated authorization codes in seconds (default = 5 minutes).
 */
/**
 * @typedef {Object} TokenOptions The OAuth2Server's TokenOptions
 * @memberof module:OAuthServer
 *
 * @property {number=} accessTokenLifetime
 * Lifetime of generated access tokens in seconds (default = 1 hour)
 * @property {number=} refreshTokenLifetime
 * Lifetime of generated refresh tokens in seconds (default = 2 weeks)
 * @property {boolean=} allowExtendedTokenAttributes
 * Allow extended attributes to be set on the returned token
 * @property {{}=} requireClientAuthentication
 * Require a client secret. Defaults to true for all grant types.
 * @property {boolean=} alwaysIssueNewRefreshToken
 * Always revoke the used refresh token and issue a new one for the refresh_token grant.
 * @property {Object.<string, AbstractGrantType>=} extendedGrantTypes
 * Additional supported grant types.
 */

/**
 * @class
 * @classdesc
 * The OAuthServer class. This wrapper also implements the PKCE support,
 * to use it, check the interface [AuthorizationCode]{@link module:PKCE.AuthorizationCode}
 * @param {module:OAuthServer.OAuthServerOptions} options
 * @param {module:OAuthServer.CustomErrorResponse=} customErrorResponse
 * If you want to handle the errors for yourself, use this function
 * @memberof module:OAuthServer
 */
export default class OAuthServer {
  private readonly server: OAuth2Server;
  private readonly continueMiddleware?: ContinueMiddleware;
  private readonly customErrorResponse?: CustomErrorResponse;

  // eslint-disable-next-line require-jsdoc
  constructor(
    options: OAuthServerOptions,
    customErrorResponse?: CustomErrorResponse
  ) {
    if (!options?.model) {
      throw new InvalidArgumentError('Missing parameter: "model"');
    }

    const { continueMiddleware, ...opts } = options;

    this.continueMiddleware = continueMiddleware
      ? {
          token: continueMiddleware.token,
          authorize: continueMiddleware.authorize
        }
      : undefined;
    this.server = new OAuth2Server(opts);
    this.customErrorResponse = customErrorResponse;
  }

  /**
   *
   * @param {module:OAuthServer.AuthorizeOptions=} options The OAuth2Server's AuthorizeOptions
   * @return {module:OAuthServer.ExpressMiddleware}
   */
  public authorize(options?: AuthorizeOptions): ExpressMiddleware {
    return async (
      req: ExpressRequest,
      res: ExpressResponse,
      next: NextFunction
    ): Promise<void> => {
      try {
        const request = new Request(req);
        const response = new Response(res);

        const code = await this.server.authorize(request, response, options);
        res.locals.oauth = { code: code };

        if (this.continueMiddleware?.authorize) {
          return next();
        }

        this.handleExpressResponse(res, response);
      } catch (error) {
        this.handleError(error, res);
      }
    };
  }

  /**
   *
   * @param {module:OAuthServer.AuthenticateOptions=} options The OAuth2Server's AuthenticateOptions
   * @return {module:OAuthServer.ExpressMiddleware}
   */
  public authenticate(options?: AuthenticateOptions): ExpressMiddleware {
    return async (
      req: ExpressRequest,
      res: ExpressResponse,
      next: NextFunction
    ): Promise<void> => {
      try {
        const request = new Request(req);
        const response = new Response(res);

        const token = await this.server.authenticate(
          request,
          response,
          options
        );
        res.locals.oauth = { token };
        next();
      } catch (error) {
        this.handleError(error, res);
      }
    };
  }

  /**
   *
   * @param {module:OAuthServer.TokenOptions=} options The OAuth2Server's TokenOptions
   * @return {module:OAuthServer.ExpressMiddleware}
   */
  public token(options?: TokenOptions): ExpressMiddleware {
    return async (
      req: ExpressRequest,
      res: ExpressResponse,
      next: NextFunction
    ): Promise<void> => {
      try {
        const request = new Request(req);
        const response = new Response(res);

        const token = await this.server.token(request, response, options);
        res.locals.oauth = { token };

        if (this.continueMiddleware?.token) {
          return next();
        }

        this.handleExpressResponse(res, response);
      } catch (error) {
        this.handleError(error, res);
      }
    };
  }

  // eslint-disable-next-line require-jsdoc
  private handleExpressResponse(res: ExpressResponse, response: Response) {
    if (response.status === 302 && response?.headers?.location) {
      const { location, ...headers } = response.headers;

      res.set(headers);
      res.redirect(location);
    } else {
      res.set(response.headers);
      res.status(response?.status ?? 200).send(response.body);
    }
  }

  // eslint-disable-next-line require-jsdoc
  private handleError(error: any, res: ExpressResponse): void {
    const errorNames = [
      'unsupported_response_type',
      'unsupported_grant_type',
      'unauthorized_request',
      'unauthorized_client',
      'insufficient_scope',
      'invalid_argument',
      'invalid_request',
      'invalid_client',
      'invalid_grant',
      'invalid_scope',
      'invalid_token',
      'access_denied',
      'server_error'
    ];

    const INTERNAL_MESSAGE = 'Internal Server Error';
    const INTERNAL_STATUS = 500;

    let message = INTERNAL_MESSAGE;
    let status = INTERNAL_STATUS;

    if (errorNames.includes(error?.name)) {
      message = error?.message ?? message;
      status = error?.code ?? status;
    }

    if (this.customErrorResponse) {
      return this.customErrorResponse(
        res,
        status >= 500 ? INTERNAL_STATUS : status,
        status >= 500 ? INTERNAL_MESSAGE : message,
        {
          status: error?.code,
          message: error?.message
        }
      );
    }

    res.status(status >= 500 ? INTERNAL_STATUS : status).json({
      success: false,
      message: status >= 500 ? INTERNAL_MESSAGE : message
    });
  }
}
