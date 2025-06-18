const AuthenticationServiceFactory = require("./authentication-service.js");

exports.authenticationHandler = async (event) => {
    if (event.httpMethod !== 'GET') {
        throw new Error(`getLoginUrl only accept GET method, you tried: ${event.httpMethod}`);
    }

    // All log statements are written to CloudWatch
    console.info('received:', event);

    const authenticationService = AuthenticationServiceFactory.getInstance();
    let response = null;

    if(event.httpMethod !== "GET" || event.path == null) {
        return authenticationService.createResponse("Page not found with http method: " + event.httpMethod + " path:" + (event.path == null ? "" : event.path), 404);
    }

    switch(event.path) {
        case "/apis/authentication/login":
            response = authenticationService.loginUrl(authenticationService.getGatewayUrl(event));
            break;
        case "/apis/authentication/status":
            response = await authenticationService.loginStatus(event.headers && event.headers["Authorization"]);
            break;
        case "/apis/authentication/logout":
            response = await authenticationService.logout(event.headers && event.headers["Authorization"]);
            break;
        case "/apis/authentication/exchange":
            const code = event.queryStringParameters && event.queryStringParameters["code"];
            if(!code) {
                response = authenticationService.createResponse("Missing code parameter", 400);
            } else {
                response = await authenticationService.exchangeCode(code, authenticationService.getGatewayUrl(event));
            }
            break;
        case "/apis/authentication/resource":
            response = await authenticationService.protectedResource(event.headers && event.headers["Authorization"]);
            break;
        default:
            response = authenticationService.createResponse("Page not found with http method: " + event.httpMethod + " path:" + (event.path == null ? "" : event.path), 404);
    }

    // All log statements are written to CloudWatch
    console.info(`response from: ${event.path} statusCode: ${response.statusCode} body: ${response.body}`);
    return response;
}


