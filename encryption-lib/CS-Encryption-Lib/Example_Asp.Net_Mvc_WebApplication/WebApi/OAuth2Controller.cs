using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Sample_Asp.Net_Mvc_WebApplication.WebApi
{
    [Route("oauth2")]
    [ApiController]
    public class Oauth2Controller : ControllerBase
    {
        [Route("v4/tokens")]
        [Route("v6/tokens")]
        [HttpPost]
        public async Task GetAccessToken()
        {
            var authorization = HttpContext.Request.Headers["Authorization"];  // Must pass in oAuth2 Bearer Token
            if (authorization.Count <= 0 || authorization[0].Length == 0)
            {
                Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            }

            //var popTokenAuthorization = HttpContext.Request.Headers["X-Authorization"];  // Must pass in PopToken
            //if (popTokenAuthorization.Count <= 0 || popTokenAuthorization[0].Length == 0)
            //{
            //    Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            //}

            // Validate ClientKey / ClientSecret
            // Todo...

            // Validate PopToken using corresponding public cert
            // Todo...

            // To simulate an oAuth2 server response, return the Token Json from local test file
            var oAuth2TokenFile = AppContext.BaseDirectory + @"TestData\oAuth2TokenResponse.json";
            var oAuth2TokenJson = System.IO.File.ReadAllText(oAuth2TokenFile);
            await Response.WriteAsync(oAuth2TokenJson);
        }
    }
}