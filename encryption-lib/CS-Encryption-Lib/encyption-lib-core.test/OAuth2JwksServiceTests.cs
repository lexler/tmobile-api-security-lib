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

using com.tmobile.oss.security.taap.poptoken.builder;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Moq.Protected;
using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe.test
{
    [TestClass]
	public class OAuth2JwksServiceTests
	{
		private HttpClient _oAuthHttpClient;
		private Mock<HttpMessageHandler> _oAuth2HttpMessageHandlerMock;
		private string _oAuthClientKey;
		private string _oAuthClientSecret;
		private string _oAuthUrl;

		private HttpClient _publicRsaHttpClient;
		private Mock<HttpMessageHandler> _publicRsaMessageHandlerMock;
		private HttpClient _publicEcHttpClient;
		private Mock<HttpMessageHandler> _publicEcHttpMessageHandlerMock;
		private string _jwkUrl;

		private PopTokenBuilder _popTokenBuilder;
		private string _privateRsaKeyXml;

		[TestInitialize]
		public void TestInitialize()
		{
			_jwkUrl = "https://somedomain.com/jwks/v1/lab/endpoint";
			_oAuthUrl = "https://somedomain.com/oauth2/v6/tokens";
			_oAuthClientKey = "SomeClientKey";
			_oAuthClientSecret = "SomeClientSecret";

			// oAuth2 Server
			var oAuth2TokenResponseJson = File.ReadAllText(@"TestData\oAuth2TokenResponse.json")
										      .Replace(Environment.NewLine, string.Empty);
			var oAuth2Response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
			{
				Content = new StringContent(oAuth2TokenResponseJson, Encoding.UTF8, "application/json")
			};
			_oAuth2HttpMessageHandlerMock = new Mock<HttpMessageHandler>();
			_oAuth2HttpMessageHandlerMock.Protected()
								    .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
								    .Returns((HttpRequestMessage request, CancellationToken cancellationToken) => { return Task.FromResult(oAuth2Response); });
			_oAuthHttpClient = new HttpClient(_oAuth2HttpMessageHandlerMock.Object, true);

			// Public RSA Jwks
			var publicRsaJwksJson = File.ReadAllText(@"TestData\JwksRSAPublic.json")
							            .Replace(Environment.NewLine, string.Empty);
			var publicRsaResponse = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
			{
				Content = new StringContent(publicRsaJwksJson, Encoding.UTF8, "application/json")
			};
			_publicRsaMessageHandlerMock = new Mock<HttpMessageHandler>();
			_publicRsaMessageHandlerMock.Protected()
								  .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
								  .Returns((HttpRequestMessage request, CancellationToken cancellationToken) => { return Task.FromResult(publicRsaResponse); });
			_publicRsaHttpClient = new HttpClient(_publicRsaMessageHandlerMock.Object, true);

			// Public EC Jwks
			var publicEcJwksJson = File.ReadAllText(@"TestData\JwksECPublic.json")
						   .Replace(Environment.NewLine, string.Empty);
			var publicEcResponse = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
			{
				Content = new StringContent(publicEcJwksJson, Encoding.UTF8, "application/json")
			};
			_publicEcHttpMessageHandlerMock = new Mock<HttpMessageHandler>();
			_publicEcHttpMessageHandlerMock.Protected()
								           .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
								           .Returns((HttpRequestMessage request, CancellationToken cancellationToken) => { return Task.FromResult(publicEcResponse); });
			_publicEcHttpClient = new HttpClient(_publicEcHttpMessageHandlerMock.Object, true);

			// PopToken
			var audience = "audience";
			var issuer = "issuer";
			_popTokenBuilder = new PopTokenBuilder(audience, issuer);
			_privateRsaKeyXml = "<RSAKeyValue><Modulus>n2da7FfnjpYVNWKtS0KMck8M50hG7VEPu/desMPsWuZTnd5XUsSCf3/++qE8EpybX4RZYMY8SqiEVGvDtzYUVWeWhLzB6YxzHkzWu3sK+5KalgOStHSRPCrAgdjcdPgRi4AhAt5aRd+8WVSJHM6c0n50OLgsrijzbj9aWYABNu2uQLiVNqYxkuEV0e+wJYR0XlSNbE9AjG4kwZw+JCeBvUH62sqg9xTDTL2DingWZC2qYq/jU25U5wMxskbuvYUCzNA4PV8fA9vJhWE5/MgRDcYWY7ajr8S3JqYoad82AOn6LBt8/4G4WQZ0z38tytWeg1/wGbOC4MktIaaEMWbAdw==</Modulus><Exponent>AQAB</Exponent><P>zbMFsT57lnHsEDlr3K5h7nIhB+CttlgBPz3wympiJ51zKfjh3Tl99L9XSNg/mpgxcTdBfzCsjMKr71OO9TGp/rl93a4PxlwaTBzUhMGbCSuoYCxVzMIAywuFSDJvnuk5IAhVlWV7Nsi+2wz1wTfWBIXqWubZjiKzqYf5QW4+lg8=</P><Q>xmIvRzMQgqGFT0l0O9O/9pJjC7qk1riqSczClOoYwG183OlOa3xguHyDw6gC19ggsKtyBKDT+mgY2ppdnTbbJk1TIDdCagD3T3iaBiEad6m7Fs+HRdJO9sVOx7r8l9ocggKJuPBL7AscYvIIosmC+GV5sbUxIX71b01mNiYFVxk=</Q><DP>RuMP7iIDQzhlSr4PHtD1rM+l9GoIU1OGsn2tEoSQ6OgIvQkpBSz/7C1YbiEf4i3atBJ/vs5OWH/p8qMQHA2OcNsJtjB6/TfWVC6HSmzR+doSv3nn45Vj4pVIzDWdY90ps5FLtR1w1dNeemy/8GNGnO5tcgAmLyZkVeMnEdZlOR8=</DP><DQ>WB+VUNNmKiEFzsqaT1kolKdCSBuIzbkKK+5BIVU72X7JUHhy1VxSuqDVBzzCxo7DNrdx1ox6nWlQYQrhOsz7XHBM1Kq3Xc9ADJVOFhruXumOqftV47YgTY4oCKEPQ4Un1Li75OMZVqk42tsY6vcIrr6k6EPMp0x2ShLfrH4HMUE=</DQ><InverseQ>ip2YXm8yrDpWOSeL5fnqtA0zFnLc28Bxc47RRcy3jjMPQ9ADfRXfa087Te+WzG0p1wZJWSpTINQjTX+BdUMpmicgU7iX/QDDAVuvKImbb9TBCO0D9OZ+fnogq03MwerZyTuws2pS5BEytgdlcTYG+w+prDZi0ll8U+EQgWeaFUQ=</InverseQ><D>XOpJBITE08dF+4VWUA0tgp/zfIkT1tcuXbl2d4Dsr5ucV+Q3cGZdTuaUARGky5B/vLCPzKogkMAjynW6cnvSZGnqQdspCPK2U44kiMnTAAtXkmPoysk7sx+UcNuwvXmv+GmqVFq5sgsVZdixx5njrYrKQhmQ6b+zDateBddoXdRH+N9RrU5lwzqhwPnswO79cjPkHd5+3H/2dirNXa5VNK0ykdGd6f0V5aesDcZwl/96VGgOX9T23Ghf4gNt2JoAcp4wKwz2u0AUgM4sJP13FXbfRhB61c9aBjldzoTVpNZofI7xADxjVWl4HRdFB+5e3xGTbDbRU/Vl/4RWpO2c0Q==</D></RSAKeyValue>";
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetJsonWebKeyListAsync_PublicRSA_Success()
		{
			// Arrange
			var jwksService = new OAuth2JwksService(_oAuthHttpClient, _oAuthClientKey, _oAuthClientSecret, _oAuthUrl, _publicRsaHttpClient, _jwkUrl);

			// Act
			var jwksList = await jwksService.GetJsonWebKeyListAsync();

			// Assert
			Assert.IsNotNull(jwksList);
			Assert.IsTrue(jwksList.Count == 1);

			Assert.AreEqual("RSA", jwksList[0].Kty);
			Assert.AreEqual(false, jwksList[0].HasPrivateKey);
			Assert.AreEqual("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwksList[0].N);
			Assert.AreEqual("AQAB", jwksList[0].E);
			Assert.AreEqual("RS256", jwksList[0].Alg);
			Assert.AreEqual("3072F4C6-193D-481B-BDD2-0F09F5A7DDFB", jwksList[0].Kid);
			Assert.AreEqual(2048, jwksList[0].KeySize);
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetJsonWebKeyListAsync_PublicEC_Success()
		{
			// Arrange
			var jwksService = new OAuth2JwksService(_oAuthHttpClient, _oAuthClientKey, _oAuthClientSecret, _oAuthUrl, _publicEcHttpClient, _jwkUrl);

			// Act
			var jwksList = await jwksService.GetJsonWebKeyListAsync();

			// Assert
			Assert.IsNotNull(jwksList);
			Assert.IsTrue(jwksList.Count == 1);

			Assert.AreEqual("EC", jwksList[0].Kty);
			Assert.AreEqual(false, jwksList[0].HasPrivateKey);
			Assert.AreEqual("P-256", jwksList[0].Crv);
			Assert.AreEqual("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jwksList[0].X);
			Assert.AreEqual("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jwksList[0].Y);
			Assert.AreEqual("enc", jwksList[0].Use);
			Assert.AreEqual("B7B4F5C7-2B46-4F54-A81A-51E8A886B094", jwksList[0].Kid);
			Assert.AreEqual(256, jwksList[0].KeySize);
		}


		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetJsonWebKeyListAsync_PublicRSA_WithPopToken_Success()
		{
			// Arrange
			var jwksService = new OAuth2JwksService(_popTokenBuilder, _privateRsaKeyXml, _oAuthHttpClient, _oAuthClientKey, _oAuthClientSecret, _oAuthUrl, _publicRsaHttpClient, _jwkUrl);

			// Act
			var jwksList = await jwksService.GetJsonWebKeyListAsync();

			// Assert
			Assert.IsNotNull(jwksList);
			Assert.IsTrue(jwksList.Count == 1);

			Assert.AreEqual("RSA", jwksList[0].Kty);
			Assert.AreEqual(false, jwksList[0].HasPrivateKey);
			Assert.AreEqual("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwksList[0].N);
			Assert.AreEqual("AQAB", jwksList[0].E);
			Assert.AreEqual("RS256", jwksList[0].Alg);
			Assert.AreEqual("3072F4C6-193D-481B-BDD2-0F09F5A7DDFB", jwksList[0].Kid);
			Assert.AreEqual(2048, jwksList[0].KeySize);
		}

	}
}