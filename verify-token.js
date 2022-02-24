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

const transpileToComEmail = (email) =>
email.endsWith("@sequoiacap.cn")
  ? email.replace("@sequoiacap.cn", "@sequoiacap.com")
  : email;


module.exports.transpileToComEmail = transpileToComEmail;
module.exports.verifyAccessToken = function verifyAccessToken(accessToken, event, context,allowAccess) {
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
          console.error("Decoded Okta token is " + JSON.stringify(decoded));
          return context.fail('Unauthorized');
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
            return context.fail('Unauthorized');;
          });
        });
      }
    });
}


