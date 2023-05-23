const { ioc } = require('@toxo/ioc');

class JwtStrategy {
  constructor(options = {}) {
    this.name = 'jwt';
    this.options = options;
    this.allowCookie = this.options.allowCookie !== false;
    this.cookieName = this.options.cookieName || 'auth_token';
    this.allowParam = this.options.allowParam !== false;
    this.paramName = this.options.paramName || 'auth_token';
    this.fail = options.fail;
    this.error = options.error;
    this.verify = options.verify;
    this.success = options.success;
    this.vault = options.vault || ioc.get('certificateVault');
  }

  static getTokenFromHeader(req) {
    if (!req?.headers?.authorization) {
      return undefined;
    }
    const parts = req.headers.authorization.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      return undefined;
    }
    return parts[1];
  }

  static getTokenFromCookie(req, cookieName) {
    return req?.cookies?.[cookieName];
  }

  static getTokenFromQuery(req, paramName) {
    return req?.query?.[paramName];
  }

  authenticate(req) {
    let token = JwtStrategy.getTokenFromHeader(req);
    if (!token && this.allowCookie) {
      token = JwtStrategy.getTokenFromCookie(req, this.cookieName);
    }
    if (!token && this.allowParam) {
      token = JwtStrategy.getTokenFromQuery(req, this.paramName);
    }
    if (!token || !token.includes('.')) {
      return this.fail(new Error('No valid authorization token'));
    }
    return this.vault
      .verifyToken(token)
      .then((data) => {
        if (!this.verify) {
          this.success(data);
        } else {
          try {
            this.verify(req, data, (err, user, info) => {
              if (err) {
                this.error(err);
              } else if (!user) {
                this.fail(info);
              } else {
                this.success(user, info);
              }
            });
          } catch (errVerify) {
            this.error(errVerify);
          }
        }
      })
      .catch((err) => {
        this.fail(err);
      });
  }
}

module.exports = {
  JwtStrategy,
};
