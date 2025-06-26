
const { authenticationHandler } = require('../authentication-handler');
const AuthenticationServiceFactory = require('../authentication-service');

jest.mock('../authentication-service', () => {
  const mockService = {
    loginUrl: jest.fn().mockResolvedValue({ statusCode: 200, body: '' }),
    loginStatus: jest.fn().mockResolvedValue({ statusCode: 200, body: '' }),
    logout: jest.fn().mockResolvedValue({ statusCode: 200, body: '' }),
    exchangeCode: jest.fn().mockResolvedValue({ statusCode: 200, body: '' }),
    protectedResource: jest.fn().mockResolvedValue({ statusCode: 200, body: '' }),
    refreshToken: jest.fn().mockResolvedValue({ statusCode: 200, body: '' }),
    createResponse: jest.fn((body, statusCode) => ({ body, statusCode })),
    getGatewayUrl: jest.fn(),
  };
  return {
    getInstance: jest.fn(() => mockService),
  };
});

describe('authenticationHandler', () => {
  let mockService;

  beforeEach(() => {
    mockService = AuthenticationServiceFactory.getInstance();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should call loginUrl for /login path', async () => {
    const event = { httpMethod: 'GET', path: '/apis/authentication/login' };
    await authenticationHandler(event);
    expect(mockService.loginUrl).toHaveBeenCalled();
  });

  it('should call loginStatus for /status path', async () => {
    const event = { httpMethod: 'GET', path: '/apis/authentication/status', headers: { Authorization: 'Bearer test' } };
    await authenticationHandler(event);
    expect(mockService.loginStatus).toHaveBeenCalledWith('Bearer test');
  });

  it('should call logout for /logout path', async () => {
    const event = { httpMethod: 'GET', path: '/apis/authentication/logout', headers: { Authorization: 'Bearer test' } };
    await authenticationHandler(event);
    expect(mockService.logout).toHaveBeenCalledWith('Bearer test');
  });

  it('should call exchangeCode for /exchange path with code', async () => {
    const event = { httpMethod: 'GET', path: '/apis/authentication/exchange', queryStringParameters: { code: 'test-code' } };
    await authenticationHandler(event);
    expect(mockService.exchangeCode).toHaveBeenCalledWith('test-code', undefined);
  });

  it('should return 400 for /exchange path without code', async () => {
    const event = { httpMethod: 'GET', path: '/apis/authentication/exchange' };
    await authenticationHandler(event);
    expect(mockService.createResponse).toHaveBeenCalledWith('Missing code parameter', 400);
  });

  it('should call protectedResource for /resource path', async () => {
    const event = { httpMethod: 'GET', path: '/apis/authentication/resource', headers: { Authorization: 'Bearer test' } };
    await authenticationHandler(event);
    expect(mockService.protectedResource).toHaveBeenCalledWith('Bearer test');
  });

  it('should call refreshToken for /refresh path', async () => {
    const event = { httpMethod: 'GET', path: '/apis/authentication/refresh', headers: { Authorization: 'Bearer test' } };
    await authenticationHandler(event);
    expect(mockService.refreshToken).toHaveBeenCalledWith('Bearer test');
  });

  it('should return 404 for unknown path', async () => {
    const event = { httpMethod: 'GET', path: '/unknown' };
    await authenticationHandler(event);
    expect(mockService.createResponse).toHaveBeenCalledWith('Page not found with http method: GET path:/unknown', 404);
  });

  it('should throw an error for non-GET requests', async () => {
    const event = { httpMethod: 'POST', path: '/login' };
    await expect(authenticationHandler(event)).rejects.toThrow('getLoginUrl only accept GET method, you tried: POST');
  });
});
