const { Strategy: SamlStrategy } = require('passport-saml');

class MultiSamlStrategy extends SamlStrategy {
  constructor (fetchSamlOptions, verify) {
    if (typeof fetchSamlOptions != 'function') {
      throw new Error('Please provide a finder method');
    }

    super(verify);
    this._fetchSamlOptions = fetchSamlOptions;
  }

  async authenticate (req, options = {}) {
    const samlOptions = await this._fetchSamlOptions(req);
    this._saml = new this._saml.constructor(samlOptions);
    this._passReqToCallback = !!samlOptions.passReqToCallback;
    this._authnRequestBinding = samlOptions.authnRequestBinding || 'HTTP-Redirect';
    return super.authenticate(req, options);
  }
}

module.exports = { Strategy: MultiSamlStrategy };
