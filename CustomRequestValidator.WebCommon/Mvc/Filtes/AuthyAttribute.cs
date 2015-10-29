using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WebGrease.Css.Extensions;

namespace CustomRequestValidator.WebCommon.Mvc.Filtes
{
    public class AuthyAttribute : ActionFilterAttribute
    {
        private readonly string _apiKey;

        public AuthyAttribute()
        {
            _apiKey = ConfigurationManager.AppSettings["AuthyKey"] ?? String.Empty;
        }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (!Validate(filterContext.HttpContext.Request))
            {
                throw new InvalidOperationException("Untrusted Request Origin");
            }

            base.OnActionExecuting(filterContext);
        }


        public bool Validate(HttpRequestBase request)
        {
            var nonce = request.Headers["X-Authy-Signature-Nonce"];
            var url = string.Format("{0}://{1}{2}",
                request.Url.Scheme, request.Headers["X-Original-Host"], request.Url.AbsolutePath);
            var serialized = Serialize(Sort(Parameters(request))).Trim('&');

            var data = string.Format("{0}|{1}|{2}|{3}",
                nonce, request.HttpMethod, url, serialized);

            var digest = ComputeDigest(data, _apiKey);
            var authySignature = request.Headers["X-Authy-Signature"];

            return digest == authySignature;
        }


        // This little modification was just in order to gain time
        private JObject Parameters(HttpRequestBase request)
        {
            request.InputStream.Position = 0;
            return (JObject)JsonConvert.DeserializeObject(new StreamReader(request.InputStream).ReadToEnd());
        }

        private static JObject Sort(JObject content)
        {
            var result = new JObject();

            // Here another modification, this time for troubles when content == null
            if (content != null)
            {
                var properties = content.Properties().OrderBy(property => property.Name);
                properties.ForEach(property =>
                {
                    var propertyValue = property.Value as JObject;
                    if (propertyValue != null)
                    {
                        result.Add(property.Name, Sort(propertyValue));
                    }
                    else
                    {
                        result.Add(property);
                    }
                }); 
            }

            return result;
        }

        private static string Serialize(JObject content)
        {
            var result = new StringBuilder();
            var properties = content.Properties();
            properties.ForEach(property =>
            {
                var propertyValue = property.Value as JObject;
                if (propertyValue != null)
                {
                    result.Append(Serialize(propertyValue));
                }
                else
                {
                    result.Append(string.Format("{0}={1}&",
                        FormatPath(property.Path), Encode(property.Value.ToString())));
                }
            });

            return result.ToString();
        }

        private static string FormatPath(string property)
        {
            var pathComponents = property.Split('.');
            var head = pathComponents[0];
            if (pathComponents.Length == 1)
            {
                return head;
            }

            var tail = pathComponents
                .Skip(1)
                .Select(component => string.Format("%5B{0}%5D", component));

            return string.Format("{0}{1}", head, string.Join("", tail));
        }

        private static string ComputeDigest(string message, string secret)
        {
            var encoding = new UTF8Encoding();
            using (var hmacsha256 = new HMACSHA256(encoding.GetBytes(secret)))
            {
                var hashedMessage = hmacsha256.ComputeHash(encoding.GetBytes(message));
                return Convert.ToBase64String(hashedMessage);
            }
        }

        private static string Encode(string content)
        {
            return content
                .Replace("@", "%40")
                .Replace("=", "%3D")
                .Replace("/", "%2F")
                .Replace("+", "%2B")
                .Replace(" ", "+")
                .Replace("False", "false");
        }
    }
}
