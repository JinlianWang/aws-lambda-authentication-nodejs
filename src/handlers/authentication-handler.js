const authenticationService = require("./authentication-service.js");

exports.authenticationHandler = async (event) => {
    if (event.httpMethod !== 'GET') {
        throw new Error(`getLoginUrl only accept GET method, you tried: ${event.httpMethod}`);
    }

    // All log statements are written to CloudWatch
    console.info('received:', event);

    let response = null;

    if(event.httpMethod !== "GET" || event.path == null) {
        return authenticationService.createResponse("Page not found with http method: " + event.httpMethod + " path:" + (event.path == null ? "" : event.path), 404);
    }

    switch(event.path) {
        case "/apis/authentication/login":
            response = authenticationService.loginUrl(authenticationService.getGatewayUrl(event));
            break;
        case "/apis/authentication/status":
            response = authenticationService.loginStatus(event["headers"]["Authorization"]);
            break;
        case "/apis/authentication/logout":
            response = authenticationService.logout(event["headers"]["Authorization"]);
            break;
        case "/apis/authentication/exchange":
            response = await authenticationService.exchangeCode(event["queryStringParameters"]["code"], authenticationService.getGatewayUrl(event));
            break;
        case "/apis/authentication/resource":
            response = await authenticationService.protectedResource(event["headers"]["Authorization"]);
            break;
        default:
            response = authenticationService.createResponse("Page not found with http method: " + event.httpMethod + " path:" + (event.path == null ? "" : event.path), 404);
    }

    // All log statements are written to CloudWatch
    console.info(`response from: ${event.path} statusCode: ${response.statusCode} body: ${response.body}`);
    return response;
}


