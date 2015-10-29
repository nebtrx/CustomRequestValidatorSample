using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CustomRequestValidatorSample.Startup))]
namespace CustomRequestValidatorSample
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
