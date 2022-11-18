require("dotenv").config();

const OktaJwtVerifier = require("@okta/jwt-verifier");
const { access } = require("fs");
const https = require("https");
const jsonWebToken = require("jsonwebtoken");

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


module.exports.transpileToComEmail = transpileToComEmail;
module.exports.verifyAccessToken = function verifyAccessToken(accessToken, event, context,allowAccess) {
  if ((event.headers && event.headers['New-Authorizer'] && event.headers['New-Authorizer'] === 'MSAL' )
    || (event.headers && event.headers['new-authorizer'] && event.headers['new-authorizer'] === 'MSAL' )) {
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
    const params = {
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

        const policy = allowAccess(event, responseBody.userPrincipalName);
        console.log(`Auth succeed as ${responseBody.userPrincipalName}`);
        const newContext = policy.build({ principalId: transpileToComEmail(responseBody.userPrincipalName) });
        console.log(JSON.stringify(newContext));
        return context.succeed(newContext);
      });

      response.on("error", (error) => {
        console.error(error);
        console.error("Decoded token is " + JSON.stringify(decoded));
        return context.fail('Unauthorized');;
      });
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
      console.log(JSON.stringify(newContext));
      return context.succeed(newContext);
      // return context.succeed(policy.build({ groups: jwt.claims.groups.join(',') }));
    })
    .catch((err) => {
      console.log(err);
      const decoded = jsonWebToken.decode(accessToken);

      console.error("Decoded Okta token is " + JSON.stringify(decoded));
      return context.fail('Unauthorized');
    });
  }
  
}


