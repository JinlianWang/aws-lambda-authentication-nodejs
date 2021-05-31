const AuthenticationServiceFactory = require("./authentication-service.js");

exports.logoutHandler = async (event) => {
    if (event.httpMethod !== 'GET') {
        throw new Error(`getLoginUrl only accept GET method, you tried: ${event.httpMethod}`);
    }

    // All log statements are written to CloudWatch
    console.info('received:', event);

    const authenticationService = AuthenticationServiceFactory.getInstance();
    const response = authenticationService.logout(authenticationService.getSessionToken(event["headers"]["Authorization"]));

    // All log statements are written to CloudWatch
    console.info(`response from: ${event.path} statusCode: ${response.statusCode} body: ${response.body}`);
    return response;
}


