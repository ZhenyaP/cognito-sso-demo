using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Web.Http.Tracing;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using NotAuthorizedException = Amazon.CognitoIdentity.Model.NotAuthorizedException;

namespace CognitoSsoDemoJs
{
    public static class AmazonCognitoHelper
    {
        private static readonly string Region = ConfigurationManager.AppSettings["AWSRegion"];
        private static readonly string PoolId = ConfigurationManager.AppSettings["PoolId"];
        private static readonly string ClientAppId = ConfigurationManager.AppSettings["ClientId"];
        private static readonly string ClientSecret = ConfigurationManager.AppSettings["ClientSecret"];
        private static readonly string CognitoTokenIssuer = $"https://cognito-idp.{Region}.amazonaws.com/{PoolId}";
        private static readonly string JwksUrl =
            $"{CognitoTokenIssuer}/.well-known/jwks.json";

        #region Private methods

        private static DateTime GetDateFromTokenTimestamp(int timestamp)
        {
            var secondsAfterBaseTime = Convert.ToInt64(Math.Truncate(Convert.ToDouble(timestamp, CultureInfo.InvariantCulture)));
            return EpochTime.DateTime(secondsAfterBaseTime);
        }

        #endregion

        public static List<UserType> GetAllUserPoolUsers()
        {
            var users = new List<UserType>();

            var provider = new AmazonCognitoIdentityProviderClient();
            string paginationToken = null;

            while (true)
            {
                var listUsersResponse = provider.ListUsers(new ListUsersRequest
                {
                    UserPoolId = PoolId,
                    PaginationToken = paginationToken
                });
                paginationToken = listUsersResponse.PaginationToken;
                users.AddRange(listUsersResponse.Users);
                if (listUsersResponse.Users.Count == 0 || string.IsNullOrEmpty(paginationToken))
                    break;
            }

            return users;
        }

        public static void CreateUser(string username)
        {
            var provider = new AmazonCognitoIdentityProviderClient();

            var createUserRequest = new AdminCreateUserRequest
            {
                MessageAction = "SUPPRESS",
                Username = username,
                TemporaryPassword = Constants.TemporaryPassword,
                UserPoolId = PoolId
            };

            provider.AdminCreateUser(createUserRequest);
        }

        public static CognitoUser ValidateUser(string username)
        {
            var provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials());
            var userPool = new CognitoUserPool(PoolId, ClientAppId, provider, ClientSecret);
            var user = new CognitoUser(username, ClientAppId, userPool, provider, ClientSecret);

            var initiateAuthRequest = new InitiateCustomAuthRequest
            {
                AuthParameters = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    {
                        CognitoConstants.ChlgParamUsername,
                        username
                    }
                },
                ClientMetadata = new Dictionary<string, string>()
            };
            if (!string.IsNullOrEmpty(ClientSecret))
                initiateAuthRequest.AuthParameters.Add(CognitoConstants.ChlgParamSecretHash,
                    Util.GetUserPoolSecretHash(username, ClientAppId, ClientSecret));

            AuthFlowResponse authResponse = user.StartWithCustomAuthAsync(initiateAuthRequest).ConfigureAwait(false)
                .GetAwaiter().GetResult();
            return authResponse.AuthenticationResult != null ? user : null;
        }

        public static CognitoUser ValidateUser(string userName, string password, string newPassword = Constants.NewPassword)
        {
            var provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials());
            var userPool = new CognitoUserPool(PoolId, ClientAppId, provider, ClientSecret);
            var user = new CognitoUser(userName, ClientAppId, userPool, provider, ClientSecret);

            var authRequest = new InitiateSrpAuthRequest
            {
                Password = password
            };

            var authResponse = user.StartWithSrpAuthAsync(authRequest).ConfigureAwait(false)
                .GetAwaiter().GetResult();

            while (authResponse.AuthenticationResult == null)
            {
                if (authResponse.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED)
                {
                    //string newPassword = "1qAz_2wsx$";

                    authResponse = user.RespondToNewPasswordRequiredAsync(new RespondToNewPasswordRequiredRequest
                    {
                        SessionID = authResponse.SessionID,
                        NewPassword = newPassword
                    }).ConfigureAwait(false).GetAwaiter().GetResult();
                }
                else
                {
                    throw new AuthenticationException($"Unrecognized authentication challenge {authResponse.ChallengeName}.");
                }
            }
            return authResponse.AuthenticationResult != null ? user : null;
        }

        public static ClaimsPrincipal ValidateAndDecryptIdToken(string jwtToken, ITraceWriter tracer)
        {
            tracer.Info(new HttpRequestMessage(), "AmazonCognitoHelper", "Hello from ValidateAndDecryptIdToken");
            var client = new HttpClient();
            var tokenSigningKeysJson = client.GetStringAsync(JwksUrl).Result;
            if (string.IsNullOrEmpty(tokenSigningKeysJson))
                throw new NotAuthorizedException($"Could not get the token signing keys for the Cognito User Pool {PoolId}");

            var tokenSigningKeys = JObject.Parse(tokenSigningKeysJson);
            //var tokenJson = Encoding.UTF8.GetString(Convert.FromBase64String(jwtToken));
            //var token = JObject.Parse(tokenJson);
            var token = new JwtSecurityToken(jwtToken);
            var keyToCheck = tokenSigningKeys["keys"].FirstOrDefault(x => (string)x["kid"] == token.Header.Kid);

            if (keyToCheck == null)
                throw new NotAuthorizedException(
                    $@"Could not find the token signing key with id {token.Header.Kid} from 
Cognito User Pool {PoolId} JWKs");
            var exponent = (string)keyToCheck["e"];
            var modulus = (string)keyToCheck["n"];
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                new RSAParameters
                {
                    Modulus = Base64UrlEncoder.DecodeBytes(modulus),
                    Exponent = Base64UrlEncoder.DecodeBytes(exponent)
                });
            var signingKey = new RsaSecurityKey(rsa);

            var parameters = new TokenValidationParameters
            {
                IssuerSigningKey = signingKey,
                ValidIssuer = CognitoTokenIssuer,
                ValidAudience = ClientAppId,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateLifetime = true,
                ValidateAudience = true,
                LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
                {
                    var validFrom = token.Payload.Iat.HasValue ? GetDateFromTokenTimestamp(token.Payload.Iat.Value) :
                        DateTime.MinValue;
                    validationParameters.LifetimeValidator = null;

                    tracer.Info(new HttpRequestMessage(), "AmazonCognitoHelper",
                        $@"validFrom = {validFrom:yyyy\'-\'MM\'-\'ddTHH\':\'mm\':\'ss zzz}; 
expires = {expires:yyyy\'-\'MM\'-\'ddTHH\':\'mm\':\'ss zzz}, 
currentTime = {DateTime.UtcNow:yyyy\'-\'MM\'-\'ddTHH\':\'mm\':\'ss zzz}");

                    Validators.ValidateLifetime(validFrom, expires, securityToken, validationParameters);
                    return true;             //if Validators.ValidateLifetime method hasn't thrown an exception, then validation passed
                },
                // This defines the maximum allowable clock skew - i.e. provides a tolerance on the token expiry time 
                // when validating the lifetime. As we're creating the tokens locally and validating them on the same 
                // machines which should have synchronised time, this can be set to zero. Where external tokens are
                // used, some leeway here could be useful.
                ClockSkew = TimeSpan.FromMinutes(0),
                RequireSignedTokens = true,
                RequireExpirationTime = true
            };
            var securityTokenHandler =
                new JwtSecurityTokenHandler { InboundClaimTypeMap = new Dictionary<string, string>() };
            var principal = securityTokenHandler.ValidateToken(jwtToken, parameters, out _);

            var tokenUseClaimValue = principal.FindFirst("token_use")?.Value;
            if (tokenUseClaimValue != "id")
                throw new NotAuthorizedException(
                    "Invalid token_use claim value for the ID token issued by Cognito User Pool");
            return principal;
        }
    }
}