using System.Linq;
using System.Security.Authentication;
using System.Web.Http;
using System.Web.Http.Tracing;
using Amazon.CognitoIdentityProvider;

namespace CognitoSsoDemoJs
{
    public class CognitoTokenController : ApiController
    {
        private readonly ITraceWriter _tracer;

        public CognitoTokenController()
        {
            _tracer = GlobalConfiguration.Configuration.Services.GetTraceWriter();
        }

        [HttpPost]
        public IHttpActionResult Login(LoginData loginData)
        {
            _tracer.Info(Request, ControllerContext.ControllerDescriptor.ControllerType.FullName, "CognitoToken Get called.");
            _tracer.Info(Request, ControllerContext.ControllerDescriptor.ControllerType.FullName, $"loginData username = {loginData.Username}");
            _tracer.Info(Request, ControllerContext.ControllerDescriptor.ControllerType.FullName, $"loginData password = {loginData.Password}");
            _tracer.Info(Request, ControllerContext.ControllerDescriptor.ControllerType.FullName, $"loginData authflow = {loginData.AuthFlow}");

            var userFoundInUserPool =
                AmazonCognitoHelper.GetAllUserPoolUsers().Any(u => u.Username == loginData.Username);
            var password = loginData.Password;
            var newPassword = Constants.NewPassword;

            if (!userFoundInUserPool)
            {
                password = Constants.TemporaryPassword;
                newPassword = loginData.Password;
                AmazonCognitoHelper.CreateUser(loginData.Username);
            }
            var user = loginData.AuthFlow == nameof(AuthFlowType.CUSTOM_AUTH) ? AmazonCognitoHelper.ValidateUser(loginData.Username) :
                loginData.AuthFlow == nameof(AuthFlowType.USER_SRP_AUTH) ? AmazonCognitoHelper.ValidateUser(loginData.Username, password, newPassword) :
                throw new AuthenticationException($"Unrecognized auth flow {loginData.AuthFlow}");

            return Json(new
            {
                token = user.SessionTokens.IdToken
            });
        }
    }
}