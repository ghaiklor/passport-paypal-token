import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';

/**
 * `Strategy` constructor.
 * The Paypal authentication strategy authenticates requests by delegating to Paypal using OAuth2 access tokens.
 * Applications must supply a `verify` callback which accepts a accessToken, refreshToken, profile and callback.
 * Callback supplying a `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurs, `error` should be set.
 *
 * Options:
 * - clientID          Identifies client to Paypal App
 * - clientSecret      Secret used to establish ownership of the consumer key
 * - passReqToCallback If need, pass req to verify callback
 *
 * @param {Object} _options
 * @param {Function} _verify
 * @example
 * passport.use(new PaypalTokenStrategy({
 *   clientID: '123456789',
 *   clientSecret: 'shhh-its-a-secret'
 * }), function(accessToken, refreshToken, profile, next) {
 *   User.findOrCreate({paypalId: profile.id}, function(error, user) {
 *     next(error, user);
 *   })
 * })
 */
export default class PaypalTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {
    let options = _options || {};
    let verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize';
    options.tokenURL = options.tokenURL || 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/tokenservice';

    super(options, verify);

    this.name = 'paypal-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._profileURL = options.profileURL || 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/userinfo?schema=openid';
    this._passReqToCallback = options.passReqToCallback;

    this._oauth2.setAccessTokenName('oauth_token');
  }

  /**
   * Authenticate method
   * @param {Object} req
   * @param {Object} options
   * @returns {*}
   */
  authenticate(req, options) {
    let accessToken = (req.body && req.body[this._accessTokenField]) || (req.query && req.query[this._accessTokenField]);
    let refreshToken = (req.body && req.body[this._refreshTokenField]) || (req.query && req.query[this._refreshTokenField]);

    if (!accessToken) return this.fail({message: `You should provide ${this._accessTokenField}`});

    this._loadUserProfile(accessToken, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        this._verify(accessToken, refreshToken, profile, verified);
      }
    });
  }

  /**
   * Parse user profile
   * @param {String} accessToken Paypal OAuth2 access token
   * @param {Function} done
   */
  userProfile(accessToken, done) {
    this._oauth2.get(this._profileURL, accessToken, function (error, body, res) {
      if (error) return done(new InternalOAuthError('Failed to fetch user profile', error.statusCode));

      try {
        let json = JSON.parse(body);
        json['id'] = json.identity.userId;

        let profile = {
          provider: 'paypal',
          id: json.id,
          displayName: [json.identity.firstName, json.identity.lastName].join(' '),
          name: {
            familyName: json.identity.lastName || '',
            givenName: json.identity.firstName || ''
          },
          emails: [],
          photos: [],
          _raw: body,
          _json: json
        };

        json.identity.emails.forEach(function (email) {
          profile.emails.push({value: email});
        });

        return done(null, profile);
      } catch (e) {
        return done(e);
      }
    });
  }
}
