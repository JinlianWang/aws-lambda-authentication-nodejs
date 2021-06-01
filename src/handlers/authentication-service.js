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
        return `https://${gatewayId}.execute-api.${process.env.AWS_REGION}.amazonaws.com/${stage}`;
    }

    SingletonClass.prototype.createResponse = function createResponse(body, statusCode) {
        let headers = {
            'Access-Control-Allow-Origin': crossAllowOrigin,
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        };
        if(statusCode === 307 || statusCode === 302 || statusCode === 303) {//Redirect needs a Location header.
            headers["Location"] = body;
        }
        return {
            statusCode: statusCode,
            headers: headers,
            body: body
        };
    }

    SingletonClass.prototype.loginUrl = function loginUrl(gatewayUrl) {
        const url = getCognitoHost() + "/oauth2/authorize?client_id="
        + cognitoAppId + "&redirect_uri=" + encodeURIComponent(getRedirectURI(gatewayUrl))
        + "&scope=openid&response_type=code";
        return this.createResponse(url,200);
    }

    SingletonClass.prototype.exchangeCode = function exchangeCode(code, gatewayUrl) {
        const params = {"code": code,
            "grant_type": "authorization_code",
            "redirect_uri": getRedirectURI(gatewayUrl)};
        const headers = {"Content-Type": "application/x-www-form-urlencoded",
            "Authorization": getBase64EncodedCredential()};
        const options = {
            hostname: getCognitoHost(true),
            port: 443,
            path: "/oauth2/token",
            method: 'POST',
            headers: headers
        };
        //console.info('Options:', options); //Debugging only; do not print out in production as it contains secrets in Authorization header.
        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
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
                            const response = this.createResponse(loginRedirectUrl + "?session=" + sessionInfo["id"], 307);
                            resolve(response);
                        });
                    } else {
                        reject(new Error('Request error:' + resString));
                    }
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

    SingletonClass.prototype.loginStatus = function loginStatus(authorizationHeader) {
        const sessionToken = getSessionToken(authorizationHeader);
        if(sessionInfo != null && (sessionInfo.id === sessionToken) && (sessionInfo.expirationTime > Date.now())) {//Session not expired yet
            return this.createResponse(JSON.stringify(sessionInfo), 200);
        }
        return this.createResponse("{}", 200);
    }

    SingletonClass.prototype.protectedResource = function protectedResource(authorizationHeader) {
        const sessionToken = getSessionToken(authorizationHeader);
        if(sessionInfo != null && (sessionInfo.id === sessionToken) && (sessionInfo.expirationTime > Date.now())) {//Session not expired yet
            return this.createResponse("Protected Resource Retrieved from DB.", 200);
        }
        return this.createResponse("", 401);
    }


    SingletonClass.prototype.logout = function logout(authorizationHeader) {
        const sessionToken = getSessionToken(authorizationHeader);
        if(sessionInfo != null && (sessionInfo.id === sessionToken)) {
            sessionInfo = null;
        }
        return this.createResponse("", 200);
    }

    function getSessionToken(authorizationHeader) {
        //Authorization header has the format of "Bearer <session token>".
        if(authorizationHeader == null || authorizationHeader.length === 0) {
            return "";
        }
        const parts = authorizationHeader.split(" ");
        if(parts != null && (parts.length === 2) && (parts[0] === "Bearer")) {
            return parts[1];
        }
        return "";
    }

    function getUserInfo(access_token) {
        //Request user info from Cognito.
        const headers = {"Authorization": "Bearer " + access_token};
        return new Promise(function (resolve, reject) {
            https.get(getCognitoHost() + "/oauth2/userInfo", {headers: headers}, (res) => {
                if (res.statusCode < 200 || res.statusCode > 299) {
                    return reject(new Error(`HTTP status code ${res.statusCode}`))
                }

                const body = []
                res.on('data', (chunk) => body.push(chunk))
                res.on('end', () => {
                    const resString = Buffer.concat(body).toString();
                    const response = JSON.parse(resString);
                    if(response != null && response["sub"] != null) {
                        resolve(response);
                    } else {
                        reject(new Error('Request error:' + resString));
                    }
                })
            }).on('error', (e) => {
                reject(e);
            })
        });
    }

    function getCognitoHost(noPrefix) {
        if(noPrefix != null && noPrefix === true) {
            return cognitoDomainPrefix + ".auth.us-east-1.amazoncognito.com"
        }
        return "https://" + cognitoDomainPrefix + ".auth.us-east-1.amazoncognito.com"
    }

    function getRedirectURI(gatewayUrl) {
        return (gatewayUrl != null ? gatewayUrl : apiGatewayUrl) + "/apis/authentication/exchange";
    }

    function getBase64EncodedCredential() {
        return "Basic " + btoaImplementation(cognitoAppId + ":" + cognitoAppSecret);
    }

    function btoaImplementation(str) {
        try {
            return btoa(str);
        } catch(err) {
            return Buffer.from(str).toString("base64"); //btoa is not implemented in node.js.
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
