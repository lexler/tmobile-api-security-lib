using com.tmobile.oss.security.taap.jwe;
using com.tmobile.oss.security.taap.poptoken.builder;
using Example_Asp.Net_Mvc_WebApplication.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;

namespace Example_Asp.Net_Mvc_WebApplication
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            // IHttpClientFactory
            services.AddHttpClient();                           

            // ILogger
            services.AddLogging();                              

            // IOptions
            services.AddOptions();                             
            var encryptionOptionsSection = Configuration.GetSection(nameof(EncryptionOptions));
            services.Configure<EncryptionOptions>(encryptionOptionsSection);
            var encryptionOptions = encryptionOptionsSection.Get<EncryptionOptions>();

            //// Can use Jwks Service (no oAuth token)
            //services.AddSingleton(serviceProvider =>
            //{
            //    var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
            //    return new JwksService(httpClientFactory.CreateClient(), encryptionOptions.JwksUrl);
            //});

            //// Or can use KeyVault Jwks Service (if oAuth token is needed for KeyVault Jwks Service)
            //services.AddSingleton(serviceProvider =>
            //{
            //    var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
            //    var oAuthUrl = encryptionOptions.oAuthUrl;
            //    var oAuthClientKey = encryptionOptions.oAuthClientKey;
            //    var oAuthClientSecret = encryptionOptions.oAuthClientSecret;
            //    return new KeyVaultJwksService(httpClientFactory.CreateClient(), oAuthClientKey, oAuthClientSecret, oAuthUrl, httpClientFactory.CreateClient(), encryptionOptions.JwksUrl);
            //});

            // Or use KeyVault Jwks Service (if oAuth token is needed for KeyVault Jwks Service, which requires a PopToken)
            services.AddTransient<IPopTokenBuilder>(serviceProvider =>
            {
                return new PopTokenBuilder(encryptionOptions.PopTokenAudience, encryptionOptions.PopTokenIssuer);
            });
            services.AddSingleton(serviceProvider =>
            {
                var popTokenBuilder = (PopTokenBuilder)serviceProvider.GetService<IPopTokenBuilder>();
                var privateKeyXml = encryptionOptions.PopTokenPrivateKeyXml;

                var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();

                var oAuthUrl = encryptionOptions.OAuthUrl;
                var oAuthClientKey = encryptionOptions.OAuthClientKey;
                var oAuthClientSecret = encryptionOptions.OAuthClientSecret;

                return new OAuth2JwksService(popTokenBuilder, privateKeyXml, httpClientFactory.CreateClient(), oAuthClientKey, oAuthClientSecret, oAuthUrl, httpClientFactory.CreateClient(), encryptionOptions.JwksUrl);
            });

            // KeyResolver
            services.AddSingleton(serviceProvider =>
            {
                //var jwksService = serviceProvider.GetService<JwksService>();  // No KeyVault, just JwksService
                var jwksService = serviceProvider.GetService<OAuth2JwksService>();  // KeyVault JwksService (with option to use oAuth2 / PopToken)

                var privateJwksJson = File.ReadAllText(@"TestData\AllPrivate.json");
                var privateJwks = JsonConvert.DeserializeObject<Jwks>(privateJwksJson);
                var privateJsonWebKeyList = new List<JsonWebKey>();
                privateJsonWebKeyList.AddRange(privateJwks.Keys);

                return new KeyResolver(privateJsonWebKeyList, jwksService, encryptionOptions.CacheDurationSeconds);
            });

            // Encryption
            services.AddTransient(serviceProvider =>
            {
                var keyResolver = serviceProvider.GetService<KeyResolver>();
                var encryptionLogger = serviceProvider.GetService<ILogger<Encryption>>();
                return new Encryption(keyResolver, encryptionLogger);
            });

            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
