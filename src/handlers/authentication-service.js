const https = require('https');
const querystring = require('querystring');
const uuid = require('uuid');

module.exports = (() => {
    function SingletonClass() {}

    const cognitoDomainPrefix = process.env.COGNITO_DOMAIN_PREFIX;
    const cognitoAppId = process.env.COGNITO_APP_ID;
    const cognitoAppSecret = process.env.COGNITO_APP_SECRET;
    const crossAllowOrigin = process.env.CORS_ALLOW_ORIGIN;
    const apiGatewayUrl = process.env.API_GATEWAY_URL;
    const loginRedirectUrl = process.env.LOGIN_REDIRECT_URL;
    let sessionInfo = null;

    SingletonClass.prototype.getGatewayUrl = function getGatewayUrl(event) {
        const gatewayId = event["requestContext"]["apiId"];
        const stage = event["requestContext"]["stage"];
        const gatewayUrl = `https://${gatewayId}.execute-api.${process.env.AWS_REGION}.amazonaws.com/${stage}`;
        return gatewayUrl;
    }

    SingletonClass.prototype.loginUrl = function loginUrl(gatewayUrl) {
        const url = getCognitoHost() + "/oauth2/authorize?client_id="
        + cognitoAppId + "&redirect_uri=" + encodeURIComponent(getRedirectURI(gatewayUrl))
        + "&scope=openid&response_type=code";
        return createResponse(url,200);
    }

    SingletonClass.prototype.exchangeCode = function exchangeCode(code) {
        const params = {"code": code,
            "grant_type": "authorization_code",
            "redirect_uri": getRedirectURI()};
        const headers = {"Content-Type": "application/x-www-form-urlencoded",
            "Authorization": getBase64EncodedCredential()};
        const options = {
            method: 'POST',
            headers: headers
        };
        return new Promise((resolve, reject) => {
            const req = https.request(getCognitoHost() + "/oauth2/token?" + querystring.stringify(params), options, (res) => {
                if (res.statusCode < 200 || res.statusCode > 299) {
                    return reject(new Error(`HTTP status code ${res.statusCode}`))
                }

                const body = []
                res.on('data', (chunk) => body.push(chunk))
                res.on('end', () => {
                    const resString = Buffer.concat(body).toString();
                    const response = JSON.parse(resString);
                    if(response != null && response["access_token"] != null) {
                        getUserInfo(response["access_token"]).then((userInfo)=>{
                            userInfo["id"] = uuid.v4();
                            userInfo["expirationTime"] = Date.now()  + 15 * 60 * 1000;  // Valid for 15 minutes
                            sessionInfo = userInfo;
                            const response = createResponse(loginRedirectUrl + "?session=" + userInfo["id"], 307);
                            resolve(response);
                        });
                    }
                    reject(new Error('Request error:' + resString));
                })
            });

            req.on('error', (err) => {
                reject(err);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request time out'));
            });

            req.write(querystring.stringify(params));
            req.end();
        });
    }

    SingletonClass.prototype.loginStatus = function loginStatus(sessionToken) {
        if(sessionInfo != null && (sessionInfo.id === sessionToken) && (sessionInfo.expirationTime > Date.now())) {
            return createResponse(JSON.stringify(sessionInfo), 200);
        }
        return createResponse("{}", 200);
    }

    SingletonClass.prototype.protectedResource = function protectedResource(sessionToken) {
        if(sessionInfo != null && (sessionInfo.id === sessionToken)) {
            return createResponse("Protected Resource Retrieved from DB.", 200);
        }
        return createResponse("", 401);
    }

    SingletonClass.prototype.getSessionToken = function getSessionToken(authorizationHeader) {
        if(authorizationHeader == null || authorizationHeader.length === 0) {
            return "";
        }
        const parts = authorizationHeader.split(" ");
        if(parts != null && (parts.length === 2) && (parts[0] === "Bearer")) {
            return parts[1];
        }
        return "";
    }

    SingletonClass.prototype.logout = function logout(sessionToken) {
        if(sessionInfo != null && (sessionInfo.id === sessionToken)) {
            sessionInfo = null;
        }
        return createResponse("", 200);
    }

    function getUserInfo(access_token) {
        const headers = {"Authorization": "Bearer " + access_token};
        return new Promise(function (resolve, reject) {
            https.get(getCognitoHost() + "/oauth2/userInfo", {headers: headers}, (res) => {
                resolve(res);
            }).on('error', (e) => {
                reject(e);
            })
        });
    }

    function createResponse(body, statusCode) {
        const headers = {
            'Access-Control-Allow-Origin': crossAllowOrigin,
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        };
        return {
            statusCode: statusCode,
            headers: headers,
            body: body
        };
    }

    function getCognitoHost() {
        return "https://" + cognitoDomainPrefix + ".auth.us-east-1.amazoncognito.com"
    }

    function getRedirectURI(gatewayUrl) {
        return (gatewayUrl != null ? gatewayUrl : apiGatewayUrl) + "/apis/authentication/exchange";
    }

    function getBase64EncodedCredential() {
        return btoaImplementation(cognitoAppId + ":" + cognitoAppSecret);
    }

    function btoaImplementation(str) {
        try {
            return btoa(str);
        } catch(err) {
            return Buffer.from(str).toString("base64");
        }
    };

    let instance;
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
