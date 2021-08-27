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

using com.tmobile.oss.security.taap.jwe.Models;
using com.tmobile.oss.security.taap.poptoken.builder;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe
{
    /// <summary>
    /// Jwks Service with OAuth2 and PopToken (optional)
    /// </summary>
    public class OAuth2JwksService : JwksService, IOAuth2JwksService
    {
        private readonly HttpClient _oAuthHttpClient;
        private readonly string _oAuthClientKey;
        private readonly string _oAuthClientSecret;
        private readonly Uri _oAuthUri;
        private readonly PopTokenBuilder _popTokenBuilder;
        private readonly string _privateKeyXml;

        /// <summary>
        /// Custom Constructor - oAuthClient option 
        /// </summary>
        /// <param name="oAuthHttpClient"></param>
        /// <param name="oAuthClientKey"></param>
        /// <param name="oAuthClientSecret"></param>
        /// <param name="oAuthUrl"></param>
        /// <param name="keyVaultJwkHttpClient"></param>
        /// <param name="keyVaultJwkUrl"></param>
        public OAuth2JwksService(HttpClient oAuthHttpClient, string oAuthClientKey, string oAuthClientSecret, string oAuthUrl, HttpClient keyVaultJwkHttpClient, string keyVaultJwkUrl)
            : base(keyVaultJwkHttpClient, keyVaultJwkUrl)
        {
            _oAuthHttpClient = oAuthHttpClient;
            _oAuthClientKey = oAuthClientKey;
            _oAuthClientSecret = oAuthClientSecret;
            _oAuthUri = new Uri(oAuthUrl);
        }

        /// <summary>
        /// Custom Constructor - oAuthClient with PopToken option 
        /// </summary>
        /// <param name="oAuthHttpClient"></param>
        /// <param name="oAuthClientKey"></param>
        /// <param name="oAuthClientSecret"></param>
        /// <param name="oAuthUrl"></param>
        /// <param name="keyVaultJwkHttpClient"></param>
        /// <param name="keyVaultJwkUrl"></param>
        public OAuth2JwksService(PopTokenBuilder popTokenBuilder, string privateKeyXml, HttpClient oAuthHttpClient, string oAuthClientKey, string oAuthClientSecret, string oAuthUrl, HttpClient keyVaultJwkHttpClient, string keyVaultJwkUrl)
            : base(keyVaultJwkHttpClient, keyVaultJwkUrl)
        {
            _popTokenBuilder = popTokenBuilder;
            _privateKeyXml = privateKeyXml;

            _oAuthHttpClient = oAuthHttpClient;
            _oAuthClientKey = oAuthClientKey;
            _oAuthClientSecret = oAuthClientSecret;
            _oAuthUri = new Uri(oAuthUrl);
        }

        /// <summary>
        /// Get JsonWebKey List from KeyVault JwksService Async
        /// </summary>
        /// <returns>List JsonWebKey</returns>
        public override async Task<List<JsonWebKey>> GetJsonWebKeyListAsync()
        {
            var accessTokenResponse = await GetAccessTokenAsync();
            var jsonWebKeyList = await GetJsonWebKeyListAync(accessTokenResponse.AccessToken);

            return jsonWebKeyList;
        }

        /// <summary>
        /// Get JsonWebKey List Aync using access token
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        private async Task<List<JsonWebKey>> GetJsonWebKeyListAync(string accessToken)
        {
            var jsonWebKeyList = new List<JsonWebKey>();

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, base.jwkUrl.PathAndQuery);
            httpRequestMessage.Headers.Add("Authorization", $"Bearer {accessToken}");
            var httpResponseMessage = await base.httpClient.SendAsync(httpRequestMessage);
            httpResponseMessage.EnsureSuccessStatusCode();

            var json = await httpResponseMessage.Content.ReadAsStringAsync();
            var jwks = JsonSerializer.Deserialize<Jwks>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            jsonWebKeyList.AddRange(jwks.Keys);

            return jsonWebKeyList;
        }

        /// <summary>
        /// Get AccessToken Async
        /// </summary>
        /// <returns></returns>
        private async Task<AuthTokenResponse> GetAccessTokenAsync()
        {
            var userIdPassword = string.Concat(_oAuthClientKey, ":", _oAuthClientSecret);
            var userIdPasswordBytes = Encoding.UTF8.GetBytes(userIdPassword);
            var authorization = $"Basic {Convert.ToBase64String(userIdPasswordBytes)}";

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, _oAuthUri);
            httpRequestMessage.Headers.Add("Authorization", authorization);

            if (_popTokenBuilder != null)
            {
                string popToken = CreatePopToken(authorization);
                httpRequestMessage.Headers.Add("X-Authorization", popToken);
            }

            var httpResponseMessage = await _oAuthHttpClient.SendAsync(httpRequestMessage);
            httpResponseMessage.EnsureSuccessStatusCode();

            var json = await httpResponseMessage.Content.ReadAsStringAsync();
            var authTokenResponse = JsonSerializer.Deserialize<AuthTokenResponse>(json);

            return authTokenResponse;
        }

        /// <summary>
        /// Create PopToken
        /// </summary>
        /// <param name="authorization"></param>
        /// <returns></returns>
        private string CreatePopToken(string authorization)
        {
            var dictionary = new Dictionary<string, string>
            {
                { PopEhtsKeyEnum.ContentType.GetDescription(), PopEhtsKeyEnum.ApplicationJson.GetDescription() },
                { PopEhtsKeyEnum.CacheControl.GetDescription(), PopEhtsKeyEnum.NoCache.GetDescription() },
                { PopEhtsKeyEnum.Authorization.GetDescription(), authorization },
                { PopEhtsKeyEnum.Uri.GetDescription(), _oAuthUri.PathAndQuery },
                { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() }
            };
            var hashMapKeyValuePair = dictionary.Set();

            return _popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                   .SignWith(_privateKeyXml)
                                   .Build();
        }
    }
}
