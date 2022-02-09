/******************************************************/
// Okta lambda authorizer for Amazon API Gateway

require("dotenv").config();

const OktaJwtVerifier = require("@okta/jwt-verifier");
const { access } = require("fs");
var https = require("https");
const jsonWebToken = require("jsonwebtoken");

/******************************************************/

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: process.env.ISSUER, // required
  clientId: process.env.CLIENT_ID, // required
  assertClaims: {
    aud: process.env.AUDIENCE,
  },
});

const AuthPolicy = require("./auth-policy");

const transpileToComEmail = (email) =>
  email.endsWith("@sequoiacap.cn")
    ? email.replace("@sequoiacap.cn", "@sequoiacap.com")
    : email;

const allowAccess = (event, email) => {
  var apiOptions = {};
  const arnParts = event.methodArn.split(":");
  const apiGatewayArnPart = arnParts[5].split("/");
  const awsAccountId = arnParts[4];
  apiOptions.region = arnParts[3];
  apiOptions.restApiId = apiGatewayArnPart[0];
  apiOptions.stage = apiGatewayArnPart[1];
  const method = apiGatewayArnPart[2];
  var resource = "/"; // root resource

  if (apiGatewayArnPart[3]) {
    resource += apiGatewayArnPart[3];
  }

  var policy = new AuthPolicy(
    transpileToComEmail(email),
    awsAccountId,
    apiOptions
  );

  /*
    removed scp check, see commit log for details
  */

  policy.allowAllMethods();

  return policy;
};

/******************************************************/

exports.handler = function (event, context) {
  var arr = event.authorizationToken.split(" ");

  var accessToken = arr[1];

  console.log("Access token: " + accessToken);

  oktaJwtVerifier
    .verifyAccessToken(accessToken, process.env.AUDIENCE)
    .then((jwt) => {
      // the token is valid (per definition of 'valid' above)
      console.log("okta request principal: " + JSON.stringify(jwt.claims));

      var policy = allowAccess(event, jwt.claims.sub);
      console.log(`Auth succeed as ${jwt.claims.sub}`);
      const newContext = policy.build({ principalId: transpileToComEmail(jwt.claims.sub) });
      console.log(JSON.stringify(newContext));
      return context.succeed(newContext);
      // return context.succeed(policy.build({ groups: jwt.claims.groups.join(',') }));
    })
    .catch((err) => {
      console.log(err);
      if (err) {
        var decoded = jsonWebToken.decode(accessToken);

        if (
          !decoded ||
          ![process.env.AAD_APPLICATION_ID, process.env.AAD_CN_APPLICATION_ID]
            .filter((value) => !!value)
            .includes(decoded.appid)
        ) {
          console.error("Decoded token is " + JSON.stringify(decoded));
          return context.fail(
            "Unauthorized due to invalid aad application id and failed Okta auth"
          );
        }
        var params = {
          host: "graph.microsoft.com",
          path: "/v1.0/me",
          port: 443,
          headers: { Authorization: `Bearer ${accessToken}` },
        };

        https.get(params, (response) => {
          let chunksOfData = [];

          response.on("data", (fragments) => {
            chunksOfData.push(fragments);
          });

          response.on("end", () => {
            let responseBody = JSON.parse(
              Buffer.concat(chunksOfData).toString()
            );
            if (responseBody.userPrincipalName != decoded.upn) {
              console.error(
                `${responseBody.userPrincipalName} do not match with ${decoded.upn}`
              );
              console.error(responseBody);
              return context.fail("Unauthorized");
            }

            var policy = allowAccess(event, responseBody.userPrincipalName);
            console.log(`Auth succeed as ${responseBody.userPrincipalName}`);
            const newContext = policy.build({ principalId: transpileToComEmail(responseBody.userPrincipalName) });
            console.log(JSON.stringify(newContext));
            return context.succeed(newContext);
          });

          response.on("error", (error) => {
            console.error(error);
            console.error("Decoded token is " + JSON.stringify(decoded));
            return context.fail("Unauthorized due to AAD auth failed");
          });
        });
      }
    });
};
