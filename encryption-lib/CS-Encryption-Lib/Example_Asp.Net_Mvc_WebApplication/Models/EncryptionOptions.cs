namespace Example_Asp.Net_Mvc_WebApplication.Models
{
    public class EncryptionOptions
    {
        public string PopTokenAudience { get; set; }
        public string PopTokenIssuer { get; set; }
        public string PopTokenPrivateKeyXml { get; set; }


        public string OAuthUrl { get; set; }
        public string OAuthClientKey { get; set; }
        public string OAuthClientSecret { get; set; }


        public string JwksUrl { get; set; }

        public int CacheDurationSeconds { get; set; }

        public string KeyPreference { get; set; }
        
    }
}
