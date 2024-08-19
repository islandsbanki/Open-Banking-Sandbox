using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


namespace Islandsbanki.OpenBanking
{
    public class Authorize
    {
        private static HttpClient AccessTokenClient = new HttpClient();
        private readonly AppConfiguration AppConfig;
        private string AuthorizationCode;
        private string State;
        static Dictionary<string,string> RefreshTokenByUserId = new Dictionary<string, string>();
        SemaphoreSlim semaphoreSlim;

        public Authorize(AppConfiguration appConfig)
        {
            AppConfig = appConfig;
            AccessTokenClient.BaseAddress = new Uri(AppConfig.AuthBaseAddress);
        }
 
        public async Task<string> AuhtorizeUser(string userId)
        {
            var (challenge, verifier) = Generate();
            State = Guid.NewGuid().ToString();

            var queryParams = new Dictionary<string, string>
            {
                {"client_id", AppConfig.ClientId},
                {"redirect_uri", AppConfig.RedirectUri},
                {"response_type", "code"},
                {"scope", AppConfig.Scopes},
                {"code_challenge", challenge},
                {"code_challenge_method", "S256"},
                {"state", State}
            };
            
            var queryParamsString = string.Join('&', queryParams.Select(q => $"{q.Key}={q.Value}"));
            var authorizationUrl = $"{AppConfig.AuthBaseAddress}{AppConfig.AuthorizationEndpoint}?{queryParamsString}";
            semaphoreSlim = new SemaphoreSlim(0);

            // Open the default web browser to the authorization URL
            OpenBrowser(authorizationUrl); 
            
            // Start a local HTTP server to capture the authorization code
            var prefixes = new[] { AppConfig.RedirectUri };
            HttpListener listener = new HttpListener();
            foreach (string s in prefixes)
            {
                listener.Prefixes.Add(s);
            }
            listener.Start();
            listener.BeginGetContext(new AsyncCallback(ListenerCallback),listener);
            Console.WriteLine("Waiting for request to be processed asyncronously.");

            await semaphoreSlim.WaitAsync();

            Console.WriteLine("Request processed asyncronously.");

            var accessToken = await ExchangeAuthorizationCodeForAccessToken(AuthorizationCode, userId, verifier);
            listener.Close();

            return accessToken;
        }
        
        public async Task<string> RefreshAccessToken(string userId)
        {
            if(!RefreshTokenByUserId.TryGetValue(userId, out string refreshToken))
            {
                return null;
            }

            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, AppConfig.TokenEndpoint);
            tokenRequest.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("refresh_token", refreshToken),
                new KeyValuePair<string, string>("client_id", AppConfig.ClientId),
                new KeyValuePair<string, string>("client_secret", AppConfig.ClientSecret),
                new KeyValuePair<string, string>("scope",  AppConfig.Scopes)
            });

            var response = await AccessTokenClient.SendAsync(tokenRequest);
            var responseContent = await response.Content.ReadAsStringAsync();
            var accessToken = JObject.Parse(responseContent)["access_token"].ToString();
            return accessToken;
        }
 
        static void OpenBrowser(string url)
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }

        void ListenerCallback(IAsyncResult result)
        {
            HttpListener listener = (HttpListener) result.AsyncState;
            HttpListenerContext context = listener.EndGetContext(result);
            HttpListenerRequest request = context.Request;
            AuthorizationCode = request?.QueryString["code"]?.ToString();
            
            if(State != request?.QueryString["state"]?.ToString())
            {
                throw new AuthenticationException("The State parameter does not match the state parameter in the request");
            }

            semaphoreSlim.Release();
        }
 
        async Task<string> ExchangeAuthorizationCodeForAccessToken(string authorizationCode, string userId, string verifier)
        {
            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, AppConfig.TokenEndpoint);
            tokenRequest.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", authorizationCode),
                new KeyValuePair<string, string>("redirect_uri", AppConfig.RedirectUri),
                new KeyValuePair<string, string>("client_id", AppConfig.ClientId),
                new KeyValuePair<string, string>("client_secret", AppConfig.ClientSecret),
                new KeyValuePair<string, string>("code_verifier", verifier)
            });

            var response = await AccessTokenClient.SendAsync(tokenRequest);
            var responseContent = await response.Content.ReadAsStringAsync();
            var refreshToken = JObject.Parse(responseContent)["refresh_token"].ToString();
            RefreshTokenByUserId.Add(userId, refreshToken);
            var accessToken = JObject.Parse(responseContent)["access_token"].ToString();
            return accessToken;
        }

        public static (string codeChallenge, string verifier) Generate(int size = 32)
        {
            using var rng = RandomNumberGenerator.Create();
            var randomBytes = new byte[size];
            rng.GetBytes(randomBytes);
            var verifier = Base64UrlEncode(randomBytes);

            var buffer = Encoding.UTF8.GetBytes(verifier);
            var hash = SHA256.Create().ComputeHash(buffer);
            var challenge = Base64UrlEncode(hash);

            return (challenge, verifier);
        }

        private static string Base64UrlEncode(byte[] data) =>
            Convert.ToBase64String(data)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');


        }
}