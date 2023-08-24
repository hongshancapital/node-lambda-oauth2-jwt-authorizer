/******************************************************/
// Okta lambda authorizer for Amazon API Gateway

require("dotenv").config();

const VerifyToken = require("./verify-token.js");

const AuthPolicy = require("./auth-policy");



const httpAllowAccess = (event, email) => {
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

const generatePolicy = function(event, effect, email) {
  var authResponse = {};
  const resource = event.methodArn;
   authResponse.principalId = email;
  if (effect) {
      var policyDocument = {};
       policyDocument.Version = '2012-10-17'; // default version
      policyDocument.Statement = [];
      var statementOne = {};
       statementOne.Action = 'execute-api:Invoke'; // default action
      statementOne.Effect = effect;
       statementOne.Resource = resource;
       policyDocument.Statement[0] = statementOne;
       authResponse.policyDocument = policyDocument;
   }   
   authResponse.build = function(context={}){
     authResponse.context=context;
     return authResponse;
   };
  return authResponse;
}
   
const wsAllowAccess = function(event, email) {
  return generatePolicy(event, 'Allow', VerifyToken.transpileToComEmail(email));
}

exports.handler = function (event, context) {
  let accessToken;
  let allowAccessFunction;
  if (event.authorizationToken) {
    accessToken = event.authorizationToken.split(" ")[1];
    allowAccessFunction = httpAllowAccess;
  } else if (event.queryStringParameters.AuthToken) {
    accessToken = event.queryStringParameters.AuthToken;
    allowAccessFunction = wsAllowAccess;
  } else {
    console.error("Invalid auth params");
  }

  console.log("Access token: " + accessToken);

  return VerifyToken.verifyAccessToken(accessToken, event, context, allowAccessFunction);
};

