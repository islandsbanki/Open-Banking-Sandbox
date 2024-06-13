using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Islandsbanki.OpenBanking
{
    public class Program
    {
        private static HttpClient Client;
        private static AppConfiguration AppConfig;
        private static string AccessToken;
        private const string InitiationPath = "payments/v2/payments/credit-transfers";
        private static Authorize Authorize;
        private static string PsuUniqueUserId = "TppIdForUser";

        protected Program()
        {              

        }

        public static async Task Main(string[] args)
        {
            Console.WriteLine($"Íslandsbanki Open Banking Demo");
            var environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");

            if(string.IsNullOrEmpty(environmentName))
            {
                Console.WriteLine($"Enter you environment name:");
                Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", Console.ReadLine());
                environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            }

            var builder = new ConfigurationBuilder()
                .AddJsonFile($"appsettings.json", true, true)
                .AddJsonFile($"appsettings.{environmentName}.json", true, true)
                .AddEnvironmentVariables();
            IConfiguration config = builder.Build();

            AppConfig = new AppConfiguration();
            config.Bind("AppConfiguration", AppConfig);

            Authorize = new Authorize(AppConfig);

            X509Certificate2 certificate = new X509Certificate2(AppConfig.QwacCertName, AppConfig.QwacCertPassword);
            HttpClientHandler handler = new ();
            handler.ClientCertificates.Add(certificate);
            Client = new HttpClient(handler)
            {
                BaseAddress = new Uri(AppConfig.PaymentBaseAddress)
            };

            bool exit = false;
            Console.WriteLine($"Your client id is {AppConfig.ClientId} running on {environmentName}");
            Console.WriteLine("Generate token? [y/N] ");

            if (Console.ReadLine().ToLower() == "y")
            {
                var token = await Authorize.AuhtorizeUser(PsuUniqueUserId);
                AccessToken = $"Bearer {token}";
            }
            
            while(!exit)
            {
                Console.WriteLine();
                Console.WriteLine("Choose an option:");
                Console.WriteLine("1 - Accounts");
                Console.WriteLine("2 - Initiate payment");
                Console.WriteLine("3 - Get payment information");
                Console.WriteLine("4 - Get payment status");
                Console.WriteLine("5 - Authorise payment");
                Console.WriteLine("6 - Cancel payment");
                Console.WriteLine("7 - Exit");

                switch (Console.ReadLine())
                {
                    case "1":
                        await GetAccounts();
                        break;
                    case "2":
                        await DoCreditTransfer();
                        break;
                    case "3":
                        Console.WriteLine("Get Payment information. Enter paymentId: ");
                        await GetPaymentInformation(paymentId: Console.ReadLine(), requestUri: null);
                        break;
                    case "4":
                        Console.WriteLine("Get Payment information status. Enter paymentId: ");
                        await GetPaymentInformationStatus(paymentId: Console.ReadLine(), requestUri: null);
                        break;
                    case "5":
                        Console.WriteLine("Authorize payment. Enter PaymentId: ");
                        await AuthorisePayment(paymentId: Console.ReadLine(), requestUri: null, authenticationMethodId: "audkenniApp");
                        break;
                    case "6":
                        Console.WriteLine("Cancel Payment. Enter PaymentId: ");
                        await CancelPayment(paymentId: Console.ReadLine(), requestUri: null);
                        break;
                    case "7":
                        exit = true;
                        break;    
                    default:
                        break;
                }          
            }   
            
            Print("Program exit", ConsoleColor.Red);
        }

        private static async Task<object> GetAccounts()
        {
            var response = await SendRequest(Program.Client, HttpMethod.Get, AppConfig.AccountsUri, "");

            Print("GET " + AppConfig.PaymentBaseAddress + AppConfig.AccountsUri, ConsoleColor.DarkYellow);

            if (response != null)
            {
                var jsonString = await response.Content.ReadAsStringAsync();
                var accounts = JsonConvert.DeserializeObject<object>(jsonString);
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject( accounts, Formatting.Indented ));
            }

            return null;
        }

        private static async Task DoCreditTransfer()
        {
            Print("We will now transfer between two accounts.");
            var validAmount = false;
            long amount = 0;

            while (!validAmount)
            {
                Print("Please enter the amount you would like to transfer: ");
                var input = Console.ReadLine();
                validAmount = long.TryParse(input, out amount);
                if (!validAmount)
                {
                    Print("Invalid amount, please try again.", ConsoleColor.Red);
                }
            }
            Print("Initiating payment of " + amount + " ISK" , ConsoleColor.Green);
            
            //Initiate payment
            var initResponse =  await InitiatePayment(amount);
            var paymentStatus = initResponse?["transactionStatus"].ToString().ToUpper();

            if(initResponse == null)
            {
                Console.WriteLine("No response. Program exists!");
                return;
            }    
            else if(paymentStatus == "RJCT")
            {
                Console.WriteLine($"Initiation failed with status {paymentStatus}. Program exists!");
                return;
            }
            else if(paymentStatus == "RCVD")
            {
                Console.WriteLine($"Initiation has status {paymentStatus}. Poll until ready for Authorization");
                var pollStatusList = new List<string>(){"ACTC", "ACFC", "RJCT"};
                if(!PollPaymentStatus(initResponse["_links"]["status"]["href"].ToString(), pollStatusList).Result)
                {
                    return;
                }
            }


            Console.WriteLine();
            Print("Choose Authentication method or cancel payment (audkenniSim is not supported on Sandbox):");            
            var authDictionary = new Dictionary<string, string>();
            int authNum = 1;
            Console.WriteLine($"{authNum++} - cancel payment");

            foreach(var auth in initResponse["scaMethods"])
            {
                var authId = auth["authenticationMethodId"].ToString();
                authDictionary.Add(authNum.ToString(), auth["authenticationMethodId"].ToString());
                Console.WriteLine($"{authNum++} - {authId}");
            }

            var authSelection = Console.ReadLine();

            if( authSelection == "1")            
            {
                await CancelPayment(null, initResponse["_links"]["self"]["href"].ToString());
                return;
            }

            authDictionary.TryGetValue(authSelection, out string authMethod);
            var requestUri = initResponse["_links"]["startAuthorisationWithAuthenticationMethodSelection"]["href"].ToString();
            var authResponse = await AuthorisePayment(paymentId: null, requestUri: requestUri, authenticationMethodId: authMethod);
            
            if(authResponse == null)
                return;                 

            Console.WriteLine( "Now polling authorisation starts");

            if(!PollAuthorizationStatus(authResponse["_links"]["scaStatus"]["href"].ToString()).Result)
                return;
            
            Console.WriteLine();

            var finalStatusList = new List<string>(){"ACCC", "RJCT"};
            if(!PollPaymentStatus(initResponse["_links"]["status"]["href"].ToString(), finalStatusList).Result)
            {
                return;
            }   
            
            Print("Fetching information about payment. Press enter to continue.");
            Console.ReadLine();
            var infoResponse = await GetPaymentInformation(null, initResponse["_links"]["self"]["href"].ToString());

            if(infoResponse == null)
                return;

            Print("Payment process is finished", ConsoleColor.DarkYellow);
        }

        private static void Print(string message = "", ConsoleColor color = ConsoleColor.White)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(message);
        }

        private static async Task<JObject> InitiatePayment(long amount)
        {
            var request = new
            {
                instructedAmount = new
                {
                    currency = "ISK",
                    amount = amount
                },
                debtorAccount = new
                {
                    iban = AppConfig.DebtorAccount
                },
                creditorAccount = new
                {
                    iban = AppConfig.CreditorAccount
                }
            };

            var requestJson = JsonConvert.SerializeObject(request);            
            var response = await SendRequest(Client, HttpMethod.Post, InitiationPath, requestJson);

            Print("POST " + AppConfig.PaymentBaseAddress + InitiationPath, ConsoleColor.DarkYellow);
            Print("Request:\n" + requestJson);

            if(response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refresh = await RefreshToken();
                if(refresh)
                {
                    response = await SendRequest(Client, HttpMethod.Post, InitiationPath, requestJson);
                }
            }

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var responseJson = JObject.Parse(responseContent);

                Print("Payment initiated successfully with id: " + responseJson["paymentId"], ConsoleColor.Green);
                Print("Response:");
                Print(responseJson.ToString());

                return responseJson;
            }
            else
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var paymentResponse = JsonConvert.DeserializeObject<Hashtable>(responseContent);

                Print("Payment initiation failed with status code: " + response.StatusCode, ConsoleColor.Red);
                Print(paymentResponse?["tppMessages"]?.ToString());

                return null;
            }           
        }
        
        private static async Task<JObject> AuthorisePayment(string paymentId, string requestUri, string authenticationMethodId)
        {
            var request = new
            {
                authenticationMethodId = authenticationMethodId
            };

            requestUri = !string.IsNullOrEmpty(requestUri) ? requestUri : $"{InitiationPath}/{paymentId}/authorisations";
            var requestJson = JsonConvert.SerializeObject(request);

            Print("POST " + AppConfig.PaymentBaseAddress + requestUri, ConsoleColor.DarkYellow);
            Print("Request:\n" + requestJson, ConsoleColor.Green);

            var response = await SendRequest(Client, HttpMethod.Post, requestUri, requestJson);

            if(response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refresh = await RefreshToken();
                if(refresh)
                {
                    response = await SendRequest(Client, HttpMethod.Post, requestUri, requestJson);
                }
            }

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var responseJson = JObject.Parse(responseContent);

                Print("Payment Authorised Successfully. Response:");
                Print(responseJson.ToString());

                return responseJson;
            }
            else
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var paymentResponse = JsonConvert.DeserializeObject<Hashtable>(responseContent);

                Print("Payment Authorization failed with status code: " + response.StatusCode, ConsoleColor.Red);
                Print(paymentResponse?["tppMessages"]?.ToString());

                return null;
            }
        }

        private static async Task<bool> PollAuthorizationStatus(string requestUri)
        {
            bool pollAuthStatus = true;
            bool authIsInFinalState = false;
            JObject authStatusResponse = null;
            Stopwatch timer = new();
            timer.Start();

            Print($"Poll the authorization [GET {AppConfig.PaymentBaseAddress}{requestUri}] status until it is in a final state <failed, exempted, finalised>");

            while(pollAuthStatus && timer.Elapsed.Seconds < 60) 
            {
                Thread.Sleep(500);
                Console.Write(".");

                authStatusResponse = await GetAuthorizationStatus(requestUri);

                if(authStatusResponse == null)
                {
                    pollAuthStatus = true;
                }

                var status = authStatusResponse?["scaStatus"].ToString().ToLower();

                if( status == "failed" || status == "exempted" || status == "finalised")
                {
                    pollAuthStatus = false;
                    authIsInFinalState = true;
                }
            }

            timer.Stop();
            Console.WriteLine();
            Print( $"Authorization status is {authStatusResponse?["scaStatus"]}" );
            Print(authStatusResponse?.ToString());

            return authIsInFinalState;
        }

        private static async Task<JObject> GetAuthorizationStatus(string requestUri)
        {
            var response = await SendRequest(Program.Client, HttpMethod.Get, requestUri, "");

            if(response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refresh = await RefreshToken();
                if(refresh)
                {
                    response = await SendRequest(Program.Client, HttpMethod.Get, requestUri, "");
                }
            }

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();

                return JObject.Parse(responseContent);
            }
            else
            {
                Print("Getting Authorization status failed with status code: " + response.StatusCode, ConsoleColor.Red);
                return null;
            }
        }

        private static async Task<bool> PollPaymentStatus(string requestUri, List<string> stopPollingStatuses)
        {
            bool pollPaymentStatus = true;
            bool paymentIsInFinalState = false;
            JObject statusResponse = null;
            Stopwatch timer = new();
            timer.Start();

            Print($"Poll the payments status [GET {AppConfig.PaymentBaseAddress}{requestUri}] until it is in the state {string.Join(" or ",stopPollingStatuses.Select(s => s))}");

            while(pollPaymentStatus && timer.Elapsed.Seconds < 60) 
            {
                Thread.Sleep(500);
                Console.Write(".");

                statusResponse = await GetPaymentInformationStatus(paymentId: null, requestUri: requestUri);

                if(statusResponse == null)
                {
                    pollPaymentStatus = true;
                }

                var paymentStatus = statusResponse?["transactionStatus"].ToString().ToUpper();
                
                if(stopPollingStatuses.Contains(paymentStatus))
                {
                    pollPaymentStatus = false;
                    paymentIsInFinalState = true;
                }
            }

            timer.Stop();
            Console.WriteLine();
            Print( $"Payment status is {statusResponse?["transactionStatus"]}" );

            return paymentIsInFinalState;
        }

        private static async Task<JObject> GetPaymentInformationStatus(string paymentId, string requestUri)
        {
            requestUri = !string.IsNullOrEmpty(requestUri) ? requestUri : $"{AppConfig.PaymentBaseAddress}{InitiationPath}/{paymentId}/status";
            var response = await SendRequest(Program.Client, HttpMethod.Get, requestUri, "");

            if(response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refresh = await RefreshToken();
                if(refresh)
                {
                    response = await SendRequest(Program.Client, HttpMethod.Get, requestUri, "");
                }
            }

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                
                return JObject.Parse(responseContent);                    
            }
            else
            {
                Print("Getting Payment status failed with status code: " + response.StatusCode, ConsoleColor.Red);
                return null;
            }
        }
           
        private static async Task<HttpResponseMessage> GetPaymentInformation(string paymentId, string requestUri)
        {
            requestUri = !string.IsNullOrEmpty(requestUri) ? requestUri : $"{AppConfig.PaymentBaseAddress}{InitiationPath}/{paymentId}";
            var response = await SendRequest(Program.Client, HttpMethod.Get, requestUri, "");

            Print("Getting payment information for payment with id: " + paymentId);
            Print("GET " + $"{AppConfig.PaymentBaseAddress}{requestUri}", ConsoleColor.DarkYellow);

            if(response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refresh = await RefreshToken();
                if(refresh)
                {
                    response = await SendRequest(Program.Client, HttpMethod.Get, requestUri, "");
                }
            }

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var paymentResponse = JsonConvert.DeserializeObject<Hashtable>(responseContent);
                Print("Payment information response:");
                foreach(var key in paymentResponse.Keys)
                {
                    Print(key + ": " + paymentResponse[key], ConsoleColor.Green);
                }
                return response;
            }
            else
            {
                Print("Failed getting payment information with status code: " + response.StatusCode, ConsoleColor.Red);
            }
            return null;
        }

        private static async Task CancelPayment(string paymentId, string requestUri)
        {
            requestUri = !string.IsNullOrEmpty(requestUri) ? requestUri : $"{AppConfig.PaymentBaseAddress}{InitiationPath}/{paymentId}";
            var response = await SendRequest(Program.Client, HttpMethod.Delete, requestUri, "");

            if(response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refresh = await RefreshToken();
                if(refresh)
                {
                    response = await SendRequest(Program.Client, HttpMethod.Get, requestUri, "");
                }
            }

            if (response.IsSuccessStatusCode)
            {
                Print($"Payment has been canceled, with status code 204-{response.StatusCode}");                    
            }
            else
            {
                Print("Cancel Payment failed with status code: " + response.StatusCode, ConsoleColor.Red);
            }
        }

        private static async Task<HttpResponseMessage> SendRequest(HttpClient Client, HttpMethod httpMethod, string requestUri, string body)
        {
            var headersToSign = new StringBuilder();
            var qsealPem = await File.ReadAllTextAsync(AppConfig.QsealPem);
            var privateKey = await File.ReadAllTextAsync(AppConfig.QsealKey);

            string xRequestId = Guid.NewGuid().ToString();
            headersToSign.Append("X-Request-Id: " + xRequestId + "\n");

            string date = DateTime.Now.ToUniversalTime().ToString("r");
            headersToSign.Append("Date: " + date + "\n");

            var digest = GetDigest(body);
            headersToSign.Append("Digest: " + digest );

            var qseal = X509Certificate2.CreateFromPem(qsealPem);
            string keyId = $"\"SN={qseal.SerialNumber}\",\"DN=\"{qseal.Issuer}\"";
            string signature = Sign(headersToSign.ToString(), privateKey);            

            string encodedQseal = Convert.ToBase64String(Encoding.UTF8.GetBytes(qsealPem));

            using (var requestMessage = new HttpRequestMessage(httpMethod, requestUri))
            {
                requestMessage.Headers.Add("X-Request-Id", xRequestId);
                requestMessage.Headers.Add("Date", date);
                requestMessage.Headers.Add("Digest", digest);
                requestMessage.Headers.Add("Signature", $"keyId={keyId},algorithm=\"rsa-sha256\",headers=\"X-Request-Id Date Digest\",signature=\"{signature}\"");
                requestMessage.Headers.Add("TPP-Signature-Certificate", encodedQseal);
                requestMessage.Headers.Add("PSU-ID","User.0");
                requestMessage.Headers.Add("PSU-IP-Address", "127.0.0.1");
                requestMessage.Headers.Add(AppConfig.AuthHeaderName, AccessToken);
                requestMessage.Headers.Add("PSU-Accept-Language", "en");
                requestMessage.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());
                requestMessage.Headers.Add("X-Audit-Guid", Guid.NewGuid().ToString("N"));
                requestMessage.Headers.Add("X-System-Id", "IBN");

                if(!string.IsNullOrEmpty(body))
                {
                    var buffer = System.Text.Encoding.UTF8.GetBytes(body);
                    var byteContent = new ByteArrayContent(buffer);
                    byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                    requestMessage.Content = byteContent;
                }

                return await Client.SendAsync(requestMessage);
            }
        }

        private static string GetDigest(string body)
        {
            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(body));

            return "SHA-256=" + Convert.ToBase64String(hash);
        }

        private static string Sign(string toSign, string privateKey)
        {
            if(privateKey.StartsWith("-----BEGIN RSA PRIVATE KEY"))
            {
                return RSASign(toSign, privateKey);
            }
            else if(privateKey.StartsWith("-----BEGIN PRIVATE KEY"))
            {
                return Pkcs8Sign(toSign, privateKey);
            }
            else
                return string.Empty;
        }

        private async static Task<bool> RefreshToken()
        {
            var token = await Authorize.RefreshAccessToken(PsuUniqueUserId);

            if(string.IsNullOrEmpty(token))
            {
                Print("Failed to refresh token");
                return false;
            }

            return true;
        }

        private static string RSASign(string toSign, string privateKey)
        {
            var privateKeyBytes = LoadPrivateKeyBytes(privateKey, "RSA PRIVATE KEY");
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKeyBytes, out var _);
            var data = Encoding.UTF8.GetBytes(toSign);
            var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var signatureBase64 = Convert.ToBase64String(signature);

            return signatureBase64;            
        }

        private static string Pkcs8Sign(string toSign, string privateKey)
        {
            var privateKeyBytes = LoadPrivateKeyBytes(privateKey, "PRIVATE KEY");
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(privateKeyBytes, out var _);
            var data = Encoding.UTF8.GetBytes(toSign);
            var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var signatureBase64 = Convert.ToBase64String(signature);

            return signatureBase64;            
        }
        
        private static byte[] LoadPrivateKeyBytes(string keyFile, string section)
        {           
            if (String.IsNullOrEmpty(keyFile))
            {
                throw new ArgumentNullException(keyFile, "Private key is missing");
            }
            
            try
            {
                byte[] data = GetBytesFromPEM(keyFile, section);
                data = data ?? Convert.FromBase64String(keyFile);

                return data;
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Error when reading pem", ex);
            }
        }
        
        private static byte[] GetBytesFromPEM( string pemString, string section )
        {
            var header = String.Format("-----BEGIN {0}-----", section);
            var footer = String.Format("-----END {0}-----", section);

            var start= pemString.IndexOf(header, StringComparison.Ordinal);
            if( start < 0 )
                return null;

            start += header.Length;
            var end = pemString.IndexOf(footer, start, StringComparison.Ordinal) - start;

            if( end < 0 )
                return null;

            return Convert.FromBase64String( pemString.Substring( start, end ) );
        }
    }
}