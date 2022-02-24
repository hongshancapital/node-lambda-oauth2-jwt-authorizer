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
  apiOptions.region = arnParts[3];
  apiOptions.restApiId = apiGatewayArnPart[0];
  apiOptions.stage = apiGatewayArnPart[1];
  const method = apiGatewayArnPart[2];
  var resource = "/"; // root resource

  if (apiGatewayArnPart[3]) {
    resource += apiGatewayArnPart[3];
  }

  var policy = new AuthPolicy(
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
  var arr = event.authorizationToken.split(" ");

  var accessToken = arr[1];

  console.log("Access token: " + accessToken);

  return VerifyToken.verifyAccessToken(accessToken, event, context, allowAccess);
};

