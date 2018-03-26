process.env.NODE_ENV = 'test';

const sinon = require('sinon');
const { expect, should } = require('chai');
const { Strategy: SamlStrategy } = require('passport-saml');
const { Strategy: MultiSamlStrategy } = require('../index');
should();

describe('Strategy()', () => {
  it('extends passport Strategy', () => {
    const fetchSamlOptions = () => ({});
    const verify = () => {};

    const strategy = new MultiSamlStrategy(fetchSamlOptions, verify);
    strategy.should.be.an.instanceOf(SamlStrategy);
  });

  it('throws if wrong finder is provided', () => {
    const verify = () => {};
    const createStrategy = () => new MultiSamlStrategy({}, verify);

    expect(createStrategy).to.throw();
  });
});

describe('strategy#authenticate', () => {
  beforeEach(() => {
    this.superAuthenticateStub = sinon.stub(SamlStrategy.prototype, 'authenticate');
  });

  afterEach(() => {
    this.superAuthenticateStub.restore();
  });

  it('calls super with request and auth options', async () => {
    const fetchSamlOptions = () => new Object();
    const verify = () => {};

    const strategy = new MultiSamlStrategy(fetchSamlOptions, verify);
    await strategy.authenticate();
    sinon.assert.calledOnce(this.superAuthenticateStub);
  });

  it('fetches the options using the finder', async () => {
    const req = { test: 'foo' };
    const verify = () => {};
    const fetchSamlOptions = sinon.stub()
      .withArgs(req).onFirstCall().returns({});

    const strategy = new MultiSamlStrategy(fetchSamlOptions, verify);
    await strategy.authenticate(req);
  });

  it('uses fetched options to setup passport options', async () => {
    const passportOptions = {
      passReqToCallback: true,
      authnRequestBinding: 'HTTP-POST'
    };
    const fetchSamlOptions = () => passportOptions;
    const verify = () => {};

    const strategy = new MultiSamlStrategy(fetchSamlOptions, verify);
    await strategy.authenticate();

    expect(strategy._passReqToCallback).to.equal(true);
    expect(strategy._authnRequestBinding).to.equal('HTTP-POST');
  });

  it('uses fetched options to setup internal saml provider', async () => {
    const samlOptions = {
      issuer: 'http://foo.issuer',
      callbackUrl: 'http://foo.callback',
      cert: 'deadbeef',
      host: 'lvh',
      acceptedClockSkewMs: -1,
      identifierFormat:
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      path: '/saml/callback',
      logoutUrl: 'http://foo.slo',
      signatureAlgorithm: 'sha256'
    };
    const fetchSamlOptions = () => samlOptions;
    const verify = () => {};

    const strategy = new MultiSamlStrategy(fetchSamlOptions, verify);
    await strategy.authenticate();

    expect(strategy._saml.options).to.include(samlOptions);
  });
});
