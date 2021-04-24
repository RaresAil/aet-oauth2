export const isPKCERequest = (request: any, grantType: string): boolean => {
  if (grantType === 'authorization_code' && request.body.code_verifier) {
    return true;
  }

  return false;
};

export const base64URLEncode = (buf: Buffer) => {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};
