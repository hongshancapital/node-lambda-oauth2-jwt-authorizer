const VerifyToken = require("./verify-token.js");

exports.wshandler = async function(event) {
   console.log('Received event:', JSON.stringify(event, null, 2));
   const queryStringParameters = event.queryStringParameters || {};
   var accessToken = queryStringParameters.AuthToken
   if(!accessToken){
      console.log(' AuthToken not fund:', JSON.stringify(event, null, 2));
      const headers = event.headers || {};
      const authorization = headers.Authorization || headers.authorization;
      if (!authorization) {
         throw new Error("Unauthorized");
      }
      const arr = authorization.split(" ");
      var accessToken = arr[1];
   }
   console.log("Access token: " + accessToken);
   return VerifyToken.verifyAccessToken(accessToken, event, wsAllowAccess);
}
    
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

