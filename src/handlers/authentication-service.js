const https = require('https');

module.exports = (function(){
    function SingletonClass() {}

    const cognitoDomainPrefix = process.env.COGNITO_DOMAIN_PREFIX;
    const cognitoAppId = process.env.COGNITO_APP_ID;
    const cognitoAppSecret = process.env.COGNITO_APP_SECRET;
    const crossAllowOrigin = process.env.CORS_ALLOW_ORIGIN;
    const apiGatewayUrl = process.env.API_GATEWAY_URL;
    const loginRedirectUrl = process.env.LOGIN_REDIRECT_URL;
    var sessionInfo = null;

    SingletonClass.prototype.cognitoAppId = cognitoAppId;

    SingletonClass.prototype.loginUrl = function loginUrl(gatewayId) {
        const url = getCognitoHost() + "/oauth2/authorize?client_id="
        + cognitoAppId + "&redirect_uri=" + encodeURIComponent(getRedirectURI())
        + "&scope=openid&response_type=code";
        return createResponse(url,200);
    }

    SingletonClass.prototype.exchangeCode = function exchangeCode(code) {

        //return session
    }

    SingletonClass.prototype.loginStatus = function loginStatus(code) {
        return sessionInfo;
    }

    SingletonClass.prototype.protectedResource = function protectedResource() {

        //return resource
    }

    SingletonClass.prototype.logout = function logout() {

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

    function getBase64EncodedCredential() {
        return btoa(cognitoAppId + ":" + cognitoAppSecret);
    }

    function getSessionToken(authorizationHeader) {
        if(authorizationHeader == null || authorizationHeader.length == 0) {
            return "";
        }
        var parts = authorizationHeader.split(" ");
        if(parts != null && (parts.length == 2) && (parts[0] == "Bearer")) {
            return parts[1];
        }
        return "";
    }

    var instance;
    return {
        getInstance: function(){
            if (instance == null) {
                instance = new SingletonClass();
                // Hide the constructor so the returned object can't be new'd...
                instance.constructor = null;
            }
            return instance;
        }
    };
})();
