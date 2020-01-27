using System.Web.Http;
using System.Web.Http.ExceptionHandling;
using System.Web.Http.Tracing;
using CognitoSsoDemoJs;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(Startup))]
namespace CognitoSsoDemoJs
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // configure web api
            var config = GlobalConfiguration.Configuration;
            config.Services.Replace(typeof(ITraceWriter), new NLogger());
            config.Services.Add(typeof(IExceptionLogger), new NLogExceptionLogger());
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{action}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            //config.Routes.MapHttpRoute(
            //    name: "LoginApi",
            //    routeTemplate: "api/CognitoToken/GetToken",
            //    defaults: new { controller = "CognitoToken", action = "GetToken" }
            //);

            config.EnsureInitialized();
            app.UseWebApi(config);
        }
    }
}