using System.Web.Http;
using System.Web.Http.ExceptionHandling;
using System.Web.Http.Tracing;
using ITraceWriter = System.Web.Http.Tracing.ITraceWriter;

namespace CognitoSsoDemoJs
{
    public class NLogExceptionLogger : ExceptionLogger
    {
        private static readonly ITraceWriter TraceWriter = GlobalConfiguration.Configuration.Services.GetTraceWriter();

        public override void Log(ExceptionLoggerContext context)
        {
            TraceWriter.Error(context.Request, nameof(NLogExceptionLogger), context.Exception);
        }
    }
}