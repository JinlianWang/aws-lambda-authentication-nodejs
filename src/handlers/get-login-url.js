const AuthenticationServiceFactory = require("./authentication-service.js");

exports.getLoginUrlHandler = async (event) => {
    if (event.httpMethod !== 'GET') {
        throw new Error(`getLoginUrl only accept GET method, you tried: ${event.httpMethod}`);
    }

    // All log statements are written to CloudWatch
    console.info('received:', event);

    const authenticationService = AuthenticationServiceFactory.getInstance();
    const response = authenticationService.loginUrl(authenticationService.getGatewayUrl(event));

    // All log statements are written to CloudWatch
    console.info(`response from: ${event.path} statusCode: ${response.statusCode} body: ${response.body}`);
    return response;
}


