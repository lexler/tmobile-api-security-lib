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
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe
{
    /// <summary>
    /// Jwks Service only.  No OAuth2, No Poptoken
    /// </summary>
    public class JwksService : IJwksService
    {
        protected readonly HttpClient _jwksServiceHttpClient;
        protected readonly Uri _jwkUrl;

        /// <summary>
        /// Custom constructor
        /// </summary>
        /// <param name="httpClient">Http Client</param>
        /// <param name="jwkUrl">JWK Server URL</param>
        public JwksService(HttpClient jwksServiceHttpClient, string jwkUrl)
        {
            _jwkUrl = new Uri(jwkUrl);
            _jwksServiceHttpClient = jwksServiceHttpClient;
            _jwksServiceHttpClient.BaseAddress = new Uri(_jwkUrl.GetLeftPart(System.UriPartial.Authority));
        }

        /// <summary>
        /// Get JsonWebKey List Async
        /// </summary>
        /// <returns>List JsonWebKey</returns>
        public virtual async Task<List<JsonWebKey>> GetJsonWebKeyListAsync()
        {
            var jsonWebKeyList = new List<JsonWebKey>();

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, _jwkUrl.PathAndQuery);
            var httpResponseMessage = await _jwksServiceHttpClient.SendAsync(httpRequestMessage);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                var json = await httpResponseMessage.Content.ReadAsStringAsync();
                var jwks = JsonSerializer.Deserialize<Jwks>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                jsonWebKeyList.AddRange(jwks.Keys);
            }

            return jsonWebKeyList;
        }
    }
}
