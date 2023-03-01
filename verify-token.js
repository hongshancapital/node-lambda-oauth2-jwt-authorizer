require("dotenv").config();

const OktaJwtVerifier = require("@okta/jwt-verifier");
const { access } = require("fs");
const https = require("https");
const jsonWebToken = require("jsonwebtoken");
const jwksClient = require('jwks-rsa');

/******************************************************/

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: process.env.ISSUER, // required
  clientId: process.env.CLIENT_ID, // required
  assertClaims: {
    aud: process.env.AUDIENCE,
  },
});

const transpileToComEmail = (email) =>
email.endsWith("@sequoiacap.cn")
  ? email.replace("@sequoiacap.cn", "@sequoiacap.com")
  : email;


const getSigningKeys = (header, callback) => {
  var client = jwksClient({
      jwksUri: 'https://login.microsoftonline.com/common/discovery/keys'
  });

  client.getSigningKey(header.kid, function (err, key) {
      var signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
  });
}


module.exports.transpileToComEmail = transpileToComEmail;
module.exports.verifyAccessToken = function verifyAccessToken(accessToken, event, context,allowAccess) {
  if ((event.headers['New-Authorizer'] && event.headers['New-Authorizer'] === 'MSAL' )
    || (event.headers['new-authorizer'] && event.headers['new-authorizer'] === 'MSAL' ) 
    || (event.queryStringParameters['newAuthorizer'] && event.queryStringParameters['newAuthorizer'] === 'MSAL' )) {
    // use MSAL to verify the token
    const decoded = jsonWebToken.decode(accessToken);
    if (
      !decoded ||
      ![process.env.AAD_APPLICATION_ID, process.env.AAD_CN_APPLICATION_ID]
        .filter((value) => !!value)
        .includes(decoded.appid)
    ) {
      console.error("Decoded MSAL token is invalid: " + JSON.stringify(decoded));
      return context.fail('Unauthorized');
    }

    const validationOptions = {
      audience: decoded.aud,
      issuer: decoded.iss
    }
    
   
    jsonWebToken.verify(accessToken, getSigningKeys, validationOptions, (err, payload) => {
      if (err) {
          console.log(err);
          console.log(JSON.stringify(event));
          return context.fail("Unauthorized");
      }
      else {
        const policy = allowAccess(event, decoded.upn);
        console.log(`Auth succeed as ${decoded.upn}`);
        const newContext = policy.build({ principalId: transpileToComEmail(decoded.upn) });
        return context.succeed(newContext);
      }

    });
  }
  else {
    // use okta
    oktaJwtVerifier
    .verifyAccessToken(accessToken, process.env.AUDIENCE)
    .then((jwt) => {
      // the token is valid (per definition of 'valid' above)
      console.log("okta request principal: " + JSON.stringify(jwt.claims));

      const policy = allowAccess(event, jwt.claims.sub);
      console.log(`Auth succeed as ${jwt.claims.sub}`);
      const newContext = policy.build({ principalId: transpileToComEmail(jwt.claims.sub) });
      return context.succeed(newContext);
    })
    .catch((err) => {
      console.log(err);
      const decoded = jsonWebToken.decode(accessToken);

      console.error("Decoded Okta token is " + JSON.stringify(decoded));
      return context.fail('Unauthorized');
    });
  }
  
}


