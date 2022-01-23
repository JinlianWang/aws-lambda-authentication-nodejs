const uuid = require('uuid');
const fetch = require('node-fetch');

const cognitoDomainPrefix = process.env.COGNITO_DOMAIN_PREFIX;
const cognitoAppId = process.env.COGNITO_APP_ID;
const cognitoAppSecret = process.env.COGNITO_APP_SECRET;
const crossAllowOrigin = process.env.CORS_ALLOW_ORIGIN;
const apiGatewayUrl = process.env.API_GATEWAY_URL;
const loginRedirectUrl = process.env.LOGIN_REDIRECT_URL;


class CognitoOAuthServices {

    #sessionInfo = null;

    getGatewayUrl(event) {
        const gatewayId = event["requestContext"]["apiId"];
        const stage = event["requestContext"]["stage"];
        return `https://${gatewayId}.execute-api.${process.env.AWS_REGION}.amazonaws.com/${stage}`;
    }

    createResponse(body, statusCode) {
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

    loginUrl(gatewayUrl) {
        const url = CognitoOAuthServices.#getCognitoHost() + "/oauth2/authorize?client_id="
        + cognitoAppId + "&redirect_uri=" + encodeURIComponent(CognitoOAuthServices.#getRedirectURI(gatewayUrl))
        + "&scope=openid&response_type=code";
        return this.createResponse(url,200);
    }

    async exchangeCode(code, gatewayUrl) {
        const params = {"code": code,
            "grant_type": "authorization_code",
            "redirect_uri": CognitoOAuthServices.#getRedirectURI(gatewayUrl)};
        const headers = {"Content-Type": "application/x-www-form-urlencoded",
            "Authorization": CognitoOAuthServices.#getBase64EncodedCredential()};

        const res = await fetch(CognitoOAuthServices.#getCognitoHost(true) + '/oauth2/token?' + new URLSearchParams(params), {
            method: 'post',
            headers: headers
        });

        const data = await res.json();
        if (data.statusCode < 200 || data.statusCode > 299) {
            throw  new Error(`HTTP status code ${data.statusCode}`);
        }
        if(data["access_token"] != null) {
            const userInfo = await CognitoOAuthServices.#getUserInfo(data["access_token"]);
            userInfo["id"] = uuid.v4();
            userInfo["expirationTime"] = Date.now()  + 15 * 60 * 1000;  // Valid for 15 minutes
            this.#sessionInfo = userInfo;
            return this.createResponse(loginRedirectUrl + "?session=" + this.#sessionInfo["id"], 307);
        } else {
            throw new Error('Request error:' + JSON.stringify(data));
        }
    }

    loginStatus(authorizationHeader) {
        const sessionToken = CognitoOAuthServices.#getSessionToken(authorizationHeader);
        if(this.#sessionInfo != null && (this.#sessionInfo.id === sessionToken) && (this.#sessionInfo.expirationTime > Date.now())) {//Session not expired yet
            return this.createResponse(JSON.stringify(this.#sessionInfo), 200);
        }
        return this.createResponse("{}", 200);
    }

    protectedResource(authorizationHeader) {
        const sessionToken = CognitoOAuthServices.#getSessionToken(authorizationHeader);
        if(this.#sessionInfo != null && (this.#sessionInfo.id === sessionToken) && (this.#sessionInfo.expirationTime > Date.now())) {//Session not expired yet
            return this.createResponse("Protected Resource Retrieved from DB.", 200);
        }
        return this.createResponse("", 401);
    }


    logout(authorizationHeader) {
        const sessionToken = CognitoOAuthServices.#getSessionToken(authorizationHeader);
        if(this.#sessionInfo != null && (this.#sessionInfo.id === sessionToken)) {
            this.#sessionInfo = null;
        }
        return this.createResponse("", 200);
    }

    static #getSessionToken(authorizationHeader) {
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

    static async #getUserInfo(access_token) {
        //Request user info from Cognito.
        const headers = {"Authorization": "Bearer " + access_token};
        const res = await fetch(CognitoOAuthServices.#getCognitoHost() + "/oauth2/userInfo", {
            method: 'get',
            headers: headers
        });

        const data = await res.json();
        if (data.statusCode < 200 || data.statusCode > 299) {
            throw  new Error(`HTTP status code ${data.statusCode}`);
        }
        if(data["sub"] != null) {
            return data; 
        } else {
            throw new Error('Request error:' + JSON.stringify(data));
        }
    }

    static #getCognitoHost(noPrefix) {
        if(noPrefix != null && noPrefix === true) {
            return cognitoDomainPrefix + ".auth.us-east-1.amazoncognito.com"
        }
        return "https://" + cognitoDomainPrefix + ".auth.us-east-1.amazoncognito.com"
    }

    static #getRedirectURI(gatewayUrl) {
        return (gatewayUrl != null ? gatewayUrl : apiGatewayUrl) + "/apis/authentication/exchange";
    }

    static #getBase64EncodedCredential() {
        return "Basic " + this.#btoaImplementation(cognitoAppId + ":" + cognitoAppSecret);
    }

    static #btoaImplementation(str) {
        try {
            return btoa(str);
        } catch(err) {
            return Buffer.from(str).toString("base64"); //btoa is not implemented in node.js.
        }
    };
}

module.exports = new CognitoOAuthServices();

