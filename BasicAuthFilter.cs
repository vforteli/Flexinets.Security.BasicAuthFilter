using log4net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Flexinets.Security
{
    public class BasicAuthFilter : Attribute, IAsyncAuthorizationFilter
    {
        private readonly ILog _log = LogManager.GetLogger(typeof(BasicAuthFilter));
        private const String Realm = "flexinetsportal";


        public Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            var request = context.HttpContext.Request;
            if (request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                var authHeaderVal = AuthenticationHeaderValue.Parse(authHeader.ToString());

                // RFC 2617 sec 1.2, "scheme" name is case-insensitive
                if (authHeaderVal.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase) && authHeaderVal.Parameter != null)
                {
                    try
                    {
                        var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authHeaderVal.Parameter)).Split(new[] { ':' });
                        if (credentials[0] == "username" && credentials[1] == "password")
                        {
                            // do nothing, maybe set user context?
                        }
                        else
                        {
                            context.HttpContext.Response.Headers.Add("WWW-Authenticate", $"Basic realm=\"{Realm}\"");
                            context.Result = new UnauthorizedResult();
                        }

                    }
                    catch (Exception ex)
                    {
                        _log.Warn("BasicAuthModule failed login", ex);
                    }
                }
            }
            else
            {
                context.HttpContext.Response.StatusCode = 401;
                context.HttpContext.Response.Headers.Add("WWW-Authenticate", $"Basic realm=\"{Realm}\"");
                context.Result = new UnauthorizedResult();
            }
            return Task.CompletedTask;
        }
    }
}

