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

using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe.test
{
	[TestClass]
	public class KeyResolverTest
	{
		private List<JsonWebKey> privateJsonWebKeyList;
		private Mock<JwksService> publicRsaJwksService;
		private Mock<JwksService> publicEcJwksService;
		private Mock<JwksService> publicOctJwksService;

		private long cacheDurationSeconds;

		[TestInitialize]
		public void TestInitialize()
		{
			var httpClient = new HttpClient();
			var jwkUrl = "http://somedomain.com/somepath";
			this.cacheDurationSeconds = 3600;

			// Public RSA Jwks
			var publicRsaJwksJson = File.ReadAllText(@"TestData\JwksRSAPublic.json");
			var publicRsaJwks = JsonConvert.DeserializeObject<Jwks>(publicRsaJwksJson);
			var publicRsaJsoneWebKeyList = new List<JsonWebKey>();
			publicRsaJsoneWebKeyList.AddRange(publicRsaJwks.Keys);
			this.publicRsaJwksService = new Mock<JwksService>(httpClient, jwkUrl);
			this.publicRsaJwksService.Setup<Task<List<JsonWebKey>>>(s => s.GetJsonWebKeyListAsync())
									 .Returns(Task.FromResult(publicRsaJsoneWebKeyList));

			// Public EC Jwks
			var publicEcJwksJson = File.ReadAllText(@"TestData\JwksECPublic.json");
			var publicEcJwks = JsonConvert.DeserializeObject<Jwks>(publicEcJwksJson);
			var publicEcJsoneWebKeyList = new List<JsonWebKey>(publicEcJwks.Keys);
			this.publicEcJwksService = new Mock<JwksService>(httpClient, jwkUrl);
			this.publicEcJwksService.Setup<Task<List<JsonWebKey>>>(s => s.GetJsonWebKeyListAsync())
									.Returns(Task.FromResult(publicEcJsoneWebKeyList));

			// Public Oct Jwks
			var publicOctJwksJson = File.ReadAllText(@"TestData\JwksOctPublic.json");
			var publicOctJwks = JsonConvert.DeserializeObject<Jwks>(publicOctJwksJson);
			var publicOctJsoneWebKeyList = new List<JsonWebKey>(publicOctJwks.Keys);
			this.publicOctJwksService = new Mock<JwksService>(httpClient, jwkUrl);
			this.publicOctJwksService.Setup<Task<List<JsonWebKey>>>(s => s.GetJsonWebKeyListAsync())
									 .Returns(Task.FromResult(publicOctJsoneWebKeyList));

			// Private RSA Key
			this.privateJsonWebKeyList = new List<JsonWebKey>();
			var privateRsaJson = File.ReadAllText(@"TestData\RsaPrivate.json");
			var privateRsaJsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(privateRsaJson);
			this.privateJsonWebKeyList.Add(privateRsaJsonWebKey);

			// Private EC key
			var privateEcJson = File.ReadAllText(@"TestData\EcPrivate.json");
			var privateEcJsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(privateEcJson);
			this.privateJsonWebKeyList.Add(privateEcJsonWebKey);

			this.cacheDurationSeconds = 3600;
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetEncryptionKeyAsync_PublicEC_Success()
		{
			// Arrange
			var keyResolver = new KeyResolver(
				new List<JsonWebKey>(), 
				this.publicEcJwksService.Object, 
				this.cacheDurationSeconds);

			// Act
			var jsonWebKey = await keyResolver.GetEncryptionKeyAsync();

			// Assert
			Assert.IsNotNull(jsonWebKey);
			Assert.IsFalse(jsonWebKey.HasPrivateKey);
			Assert.AreEqual("EC", jsonWebKey.Kty);
			Assert.AreEqual(false, jsonWebKey.HasPrivateKey);
			Assert.AreEqual("P-256", jsonWebKey.Crv);
			Assert.AreEqual("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jsonWebKey.X);
			Assert.AreEqual("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jsonWebKey.Y);
			Assert.AreEqual("enc", jsonWebKey.Use);
			Assert.AreEqual("B7B4F5C7-2B46-4F54-A81A-51E8A886B094", jsonWebKey.Kid);
			Assert.AreEqual(256, jsonWebKey.KeySize);
		}
	}
}
