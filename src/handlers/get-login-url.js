// Create clients and set shared const values outside of the handler.
const cognitoDomainPrefix = process.env.COGNITO_DOMAIN_PREFIX;
const cognitoAppId = process.env.COGNITO_APP_ID;
const crossAllowOrigin = process.env.CORS_ALLOW_ORIGIN;
const apiGatewayUrl = process.env.API_GATEWAY_URL;

exports.getLoginUrlHandler = async (event) => {
    if (event.httpMethod !== 'GET') {
        throw new Error(`getLoginUrl only accept GET method, you tried: ${event.httpMethod}`);
    }

    // All log statements are written to CloudWatch
    console.info('received:', event);

    const response = createResponse(getCognitoHost() + "/oauth2/authorize?client_id="
                          + cognitoAppId + "&redirect_uri=" + encodeURIComponent(getRedirectURI())
                          + "&scope=openid&response_type=code", 200);

    // All log statements are written to CloudWatch
    console.info(`response from: ${event.path} statusCode: ${response.statusCode} body: ${response.body}`);
    return response;
}

function createResponse(body, statusCode) {
    const headers = {
        'Access-Control-Allow-Origin': crossAllowOrigin,
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
    };
    const response = {
        statusCode: statusCode,
        headers: headers,
        body: body
    };
    return response;
}

function getCognitoHost() {
    return "https://" + cognitoDomainPrefix + ".auth.us-east-1.amazoncognito.com"
}


function getRedirectURI() {
    return apiGatewayUrl + "/apis/authentication/exchange";
}
