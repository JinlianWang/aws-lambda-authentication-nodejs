const AWS = require('aws-sdk');

jest.mock('aws-sdk', () => {
  const mockDynamoDB = {
    get: jest.fn().mockReturnThis(),
    put: jest.fn().mockReturnThis(),
    delete: jest.fn().mockReturnThis(),
    promise: jest.fn(),
  };
  return {
    DynamoDB: {
      DocumentClient: jest.fn(() => mockDynamoDB),
    },
    CognitoIdentityServiceProvider: jest.fn(() => ({
        globalSignOut: jest.fn().mockReturnThis(),
        promise: jest.fn(),
    }))
  };
});

jest.mock('https');
jest.mock('uuid');

describe('AuthenticationService', () => {
  let authenticationService;
  let mockDynamoDB;
  let https;
  let uuid;

  beforeEach(() => {
    jest.resetModules();
    https = require('https');
    uuid = require('uuid');
    process.env.COGNITO_DOMAIN_PREFIX = 'test-domain';
    process.env.COGNITO_APP_ID = 'test-app-id';
    process.env.COGNITO_APP_SECRET = 'test-app-secret';
    process.env.CORS_ALLOW_ORIGIN = 'http://localhost:4200';
    process.env.API_GATEWAY_URL = 'https://api.test.com/stage';
    process.env.LOGIN_REDIRECT_URL = 'http://localhost:4200/login';
    process.env.SESSION_TABLE = 'test-session-table';

    const AuthenticationServiceFactory = require('../authentication-service');
    authenticationService = AuthenticationServiceFactory.getInstance();
    const AWS = require('aws-sdk');
    mockDynamoDB = new AWS.DynamoDB.DocumentClient();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('loginUrl', () => {
    it('should return the correct login URL', () => {
      const gatewayUrl = 'https://api.test.com/stage';
      const response = authenticationService.loginUrl(gatewayUrl);
      expect(response.statusCode).toBe(200);
      expect(response.body).toContain('https://test-domain.auth.us-east-1.amazoncognito.com/oauth2/authorize');
    });
  });

  describe('exchangeCode', () => {
    it('should exchange code for tokens and create a session', async () => {
        const mockRequest = {
            on: jest.fn().mockReturnThis(),
            write: jest.fn().mockReturnThis(),
            end: jest.fn().mockReturnThis(),
        };
        const mockResponse = {
            statusCode: 200,
            on: jest.fn((event, callback) => {
              if (event === 'data') {
                callback(Buffer.from(JSON.stringify({ access_token: 'test-access-token', refresh_token: 'test-refresh-token' })));
              } else if (event === 'end') {
                callback();
              }
            }),
        };
        https.request.mockImplementation((options, callback) => {
            callback(mockResponse);
            return mockRequest;
        });
        https.get.mockImplementation((url, options, callback) => {
            const mockGetResponse = {
                statusCode: 200,
                on: jest.fn((event, callback) => {
                    if (event === 'data') {
                        callback(Buffer.from(JSON.stringify({ sub: 'test-sub' })));
                    } else if (event === 'end') {
                        callback();
                    }
                }),
            };
            callback(mockGetResponse);
            return mockRequest;
        });
        uuid.v4.mockReturnValue('test-uuid');
        const response = await authenticationService.exchangeCode('test-code', 'https://api.test.com/stage');
        expect(response.statusCode).toBe(307);
        expect(response.headers.Location).toBe('http://localhost:4200/login?session=test-uuid');
        expect(mockDynamoDB.put).toHaveBeenCalled();
    });
  });

  describe('loginStatus', () => {
    it('should return session info for a valid session', async () => {
      const sessionToken = 'valid-token';
      const sessionRecord = { id: sessionToken, expirationTime: Date.now() + 10000 };
      mockDynamoDB.promise.mockResolvedValueOnce({ Item: sessionRecord });
      const response = await authenticationService.loginStatus(`Bearer ${sessionToken}`);
      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body)).toEqual(sessionRecord);
    });

    it('should return empty object for an invalid session', async () => {
      const sessionToken = 'invalid-token';
      mockDynamoDB.promise.mockResolvedValueOnce({ Item: null });
      const response = await authenticationService.loginStatus(`Bearer ${sessionToken}`);
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe('{}');
    });
  });

  describe('logout', () => {
    it('should delete the session and revoke the token', async () => {
      const sessionToken = 'valid-token';
      const sessionRecord = { id: sessionToken, accessToken: 'test-access-token', expirationTime: Date.now() + 10000 };
      mockDynamoDB.promise.mockResolvedValueOnce({ Item: sessionRecord });
      const response = await authenticationService.logout(`Bearer ${sessionToken}`);
      expect(response.statusCode).toBe(200);
      expect(mockDynamoDB.delete).toHaveBeenCalledWith({ TableName: 'test-session-table', Key: { id: sessionToken } });
    });
  });

  describe('protectedResource', () => {
    it('should return the resource for a valid session', async () => {
      const sessionToken = 'valid-token';
      const sessionRecord = { id: sessionToken, expirationTime: Date.now() + 10000 };
      mockDynamoDB.promise.mockResolvedValueOnce({ Item: sessionRecord });
      const response = await authenticationService.protectedResource(`Bearer ${sessionToken}`);
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe('Protected Resource Retrieved from DB.');
    });

    it('should return 401 for an invalid session', async () => {
      const sessionToken = 'invalid-token';
      mockDynamoDB.promise.mockResolvedValueOnce({ Item: null });
      const response = await authenticationService.protectedResource(`Bearer ${sessionToken}`);
      expect(response.statusCode).toBe(401);
    });
  });

  describe('refreshToken', () => {
    it('should refresh the token and update the session', async () => {
        const mockRequest = {
            on: jest.fn().mockReturnThis(),
            write: jest.fn().mockReturnThis(),
            end: jest.fn().mockReturnThis(),
        };
        const mockResponse = {
            statusCode: 200,
            on: jest.fn((event, callback) => {
              if (event === 'data') {
                callback(Buffer.from(JSON.stringify({ access_token: 'new-access-token', refresh_token: 'new-refresh-token' })));
              } else if (event === 'end') {
                callback();
              }
            }),
        };
        https.request.mockImplementation((options, callback) => {
            callback(mockResponse);
            return mockRequest;
        });
        const sessionToken = 'valid-token';
        const sessionRecord = { id: sessionToken, refreshToken: 'test-refresh-token', expirationTime: Date.now() + 10000 };
        mockDynamoDB.promise.mockResolvedValueOnce({ Item: sessionRecord });
        const response = await authenticationService.refreshToken(`Bearer ${sessionToken}`);
        expect(response.statusCode).toBe(200);
        expect(mockDynamoDB.put).toHaveBeenCalled();
    });
  });
});