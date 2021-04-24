import { InvalidGrantError, ServerError, Request } from 'oauth2-server';
import crypto from 'crypto';

import { TYPE, AuthorizationCode } from '.';
import { base64URLEncode } from './utils';

const validateAuthCode = (request: Request, code: AuthorizationCode) => {
  if (code.codeChallenge) {
    if (!request.body.code_verifier) {
      throw new InvalidGrantError('Missing parameter: `code_verifier`');
    }

    let hash: string;
    switch (code.codeChallengeMethod) {
      case TYPE.PLAIN:
        hash = request.body.code_verifier;
        break;
      case TYPE.S256:
        hash = base64URLEncode(
          crypto
            .createHash('sha256')
            .update(request.body.code_verifier)
            .digest()
        );
        break;
      default:
        throw new ServerError(
          'Server error: `getAuthorizationCode()` did not return a valid `codeChallengeMethod` property'
        );
    }

    if (
      Buffer.from(code.codeChallenge).length !== Buffer.from(hash).length ||
      !crypto.timingSafeEqual(
        Buffer.from(code.codeChallenge),
        Buffer.from(hash)
      )
    ) {
      throw new InvalidGrantError('Invalid grant: code verifier is invalid');
    }
  } else {
    if (request.body.code_verifier) {
      throw new InvalidGrantError('Invalid grant: code verifier is invalid');
    }
  }
};

export default validateAuthCode;
