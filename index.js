/******************************************************/
// Okta lambda authorizer for Amazon API Gateway

require("dotenv").config();

const VerifyToken = require("./verify-token.js");

const AuthPolicy = require("./auth-policy");



const allowAccess = (event, email) => {
  var apiOptions = {};
  const arnParts = event.methodArn.split(":");
  const apiGatewayArnPart = arnParts[5].split("/");
  const awsAccountId = arnParts[4];
  apiOptions.start = arnParts[0] + ":" + arnParts[1] + ":"  + arnParts[2] + ":";
  apiOptions.region = arnParts[3];
  apiOptions.restApiId = apiGatewayArnPart[0];
  apiOptions.stage = apiGatewayArnPart[1];
  const method = apiGatewayArnPart[2];
  var resource = "/"; // root resource

  if (apiGatewayArnPart[3]) {
    resource += apiGatewayArnPart[3];
  }

  const policy = new AuthPolicy(
    VerifyToken.transpileToComEmail(email),
    awsAccountId,
    apiOptions
  );

  /*
    removed scp check, see commit log for details
  */

  policy.allowAllMethods();

  return policy;
};

exports.handler = function (event, context) {
  const arr = event.authorizationToken.split(" ");

  const accessToken = arr[1];

  console.log("Access token: " + accessToken);

  return VerifyToken.verifyAccessToken(accessToken, event, context, allowAccess);
};

