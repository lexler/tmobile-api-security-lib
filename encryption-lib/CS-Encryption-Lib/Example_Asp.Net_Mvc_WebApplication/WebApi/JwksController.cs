using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Sample_Asp.Net_Mvc_WebApplication.WebApi
{
    [Route("jwks")]
    [ApiController]
    public class JwksController : ControllerBase
    {
        [Route("v1/lab01/getjsonwebkeys")]
        [HttpGet]
        public async Task GetJsonWebKeyListAsync()
        {
            // To simulate an Jwks server response, return test data from local file
            var jwksFile = AppContext.BaseDirectory + @"TestData\JwksAllPublic.json";
            var jwksJson = System.IO.File.ReadAllText(jwksFile);
            await Response.WriteAsync(jwksJson);
        }
    }
}