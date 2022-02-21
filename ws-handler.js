const VerifyToken = require("./verify-token.js");

const transpileToComEmail = (email) =>
  email.endsWith("@sequoiacap.cn")
    ? email.replace("@sequoiacap.cn", "@sequoiacap.com")
    : email;


exports.wshandler = function(event, context) {        
   console.log('Received event:', JSON.stringify(event, null, 2));
   var queryStringParameters = event.queryStringParameters;
   var accessToken = queryStringParameters.AuthToken
   if(!accessToken){
      console.log(' AuthToken not fund:', JSON.stringify(event, null, 2));
      var arr = event.headers.Authorization.split(" ");
      var accessToken = arr[1];
   }
   console.log("Access token: " + accessToken);
   return VerifyToken.verifyAccessToken(accessToken, event, context,allowAccess);
}
    
var generatePolicy = function(event, effect, email) {
   var authResponse = {};
   var resource = event.methodArn;
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
    
var allowAccess = function(event, email) {
   return generatePolicy(event, 'Allow', transpileToComEmail(email));
}

