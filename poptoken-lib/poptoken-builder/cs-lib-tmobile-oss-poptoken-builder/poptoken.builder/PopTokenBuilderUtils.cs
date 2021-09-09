/*
 * Copyright 2020 T-Mobile US, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace com.tmobile.oss.security.taap.poptoken.builder
{
    /// <summary>
    /// PopToken Builder Utils
    /// </summary>
    public class PopTokenBuilderUtils
	{
		private static readonly JsonWebTokenHandler _jsonWebTokenHandler;

        /// <summary>
        /// Default Constructor
        /// </summary>
		static PopTokenBuilderUtils()
		{
            _jsonWebTokenHandler = new JsonWebTokenHandler();
		}

        /// <summary>
        /// Create Rsa Security Key
        /// </summary>
        /// <param name="rsaKeyPKCS8PemOrXml">Rsa Key PKCS8 Pem Or Xml</param>
        /// <param name="password">Password for Key (Optional)</param>
        /// <returns>RsaSecurityKey</returns>
        public static RsaSecurityKey CreateRsaSecurityKey(string rsaKeyPKCS8PemOrXml, string password = null)
        {
            var rsa = RSA.Create();
            rsa.KeySize = 2048;

            if (rsaKeyPKCS8PemOrXml.Contains("BEGIN PUBLIC KEY"))
            {
                var certificate = rsaKeyPKCS8PemOrXml.Replace("-----BEGIN PUBLIC KEY-----", "")
                                                     .Replace("-----END PUBLIC KEY-----", "")
                                                     .Replace(Environment.NewLine, "");
                var certificateBytes = Convert.FromBase64String(certificate);
                rsa.ImportSubjectPublicKeyInfo(certificateBytes, out _);
            }
            else if (rsaKeyPKCS8PemOrXml.Contains("BEGIN PRIVATE KEY"))
            {
                var certificate = rsaKeyPKCS8PemOrXml.Replace("-----BEGIN PRIVATE KEY-----", "")
                                                     .Replace("-----END PRIVATE KEY-----", "")
                                                     .Replace(Environment.NewLine, "");
                var certificateBytes = Convert.FromBase64String(certificate);
                rsa.ImportPkcs8PrivateKey(certificateBytes, out _);
            }

            if (rsaKeyPKCS8PemOrXml.Contains("BEGIN RSA PUBLIC KEY"))
            {
                var certificate = rsaKeyPKCS8PemOrXml.Replace("-----BEGIN RSA PUBLIC KEY-----", "")
                                                     .Replace("-----END RSA PUBLIC KEY-----", "")
                                                     .Replace(Environment.NewLine, "");
                var certificateBytes = Convert.FromBase64String(certificate);
                rsa.ImportRSAPublicKey(certificateBytes, out _);
            }
            else if (rsaKeyPKCS8PemOrXml.Contains("BEGIN RSA PRIVATE KEY"))
            {
                var certificate = rsaKeyPKCS8PemOrXml.Replace("-----BEGIN RSA PRIVATE KEY-----", "")
                                                     .Replace("-----END RSA PRIVATE KEY-----", "")
                                                     .Replace(Environment.NewLine, "");
                var certificateBytes = Convert.FromBase64String(certificate);
                rsa.ImportRSAPrivateKey(certificateBytes, out _);
            }


            else if (rsaKeyPKCS8PemOrXml.Contains("BEGIN ENCRYPTED PRIVATE KEY"))
            {
                var certificate = rsaKeyPKCS8PemOrXml.Replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                                                     .Replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                                                     .Replace(Environment.NewLine, "");
                var certificateBytes = Convert.FromBase64String(certificate);
                rsa.ImportEncryptedPkcs8PrivateKey(password, certificateBytes, out _);
            }

            else if (rsaKeyPKCS8PemOrXml.Contains("<") &&
                     rsaKeyPKCS8PemOrXml.Contains(">"))
            {
                rsa.FromXmlRsaPemKey(rsaKeyPKCS8PemOrXml);
            }

            return new RsaSecurityKey(rsa);
        }

        /// <summary>
        /// Validate Token
        /// </summary>
        /// <param name="popToken">PopToken</param>
        /// <param name="issuer">Issuer</param>
        /// <param name="audience">Audience</param>
        /// <param name="rsaSecurityKey">Rsa Security Key</param>
        /// <returns></returns>
        public static TokenValidationResult ValidateToken(string popToken, string issuer, string audience, RsaSecurityKey rsaSecurityKey)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidIssuer = issuer,
                ValidAudiences = new[] { audience },
                IssuerSigningKeys = new[] { rsaSecurityKey }
            };
            
            return _jsonWebTokenHandler.ValidateToken(popToken, tokenValidationParameters);
        }
    }
}
