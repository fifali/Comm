using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Sign
{
    class Program
    {
        public class RequestHelper
        {
            /// <summary>
            /// 返回值的类型，支持JSON与XML。默认为XML
            /// </summary>
            public string Format { get; set; } = "JSON";

            /// <summary>
            /// API版本号，为日期形式：YYYY-MM-DD，本版本对应为2016-05-11
            /// </summary>
            public string Version { get; } = "2014-11-11";

            /// <summary>
            /// 阿里云颁发给用户的访问服务所用的密钥ID
            /// </summary>
            public string AccessKeyId { get; set; } = "****************";

            /// <summary>
            /// 签名结果串
            /// </summary>
            public string Signature { get; set; }

            /// <summary>
            /// 签名方式，目前支持HMAC-SHA1
            /// </summary>
            public string SignatureMethod { get; } = "HMAC-SHA1";

            /// <summary>
            /// 请求的时间戳。日期格式按照ISO8601标准表示，并需要使用UTC时间。格式为YYYY-MM-DDThh:mm:ssZ例如，2015-01-09T12:00:00Z（为UTC时间2015年1月9日12点0分0秒）
            /// </summary>
            public string Timestamp { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            /// <summary>
            /// 签名算法版本，目前版本是1.0
            /// </summary>
            public string SignatureVersion { get; } = "1.0";

            /// <summary>
            /// 唯一随机数，用于防止网络重放攻击。用户在不同请求间要使用不同的随机数值
            /// </summary>
            public string SignatureNonce { get; } = Guid.NewGuid().ToString();

            /// <summary>
            ///
            /// </summary>
            private readonly HttpMethod _httpMethod;

            /// <summary>
            /// 阿里云颁发给用户的访问服务所用的密钥
            /// </summary>
            private string AccessKeySecret { get; set; } = "4txZk+mhrU/JMLXmyP5m3S4Rc20=";

            /// <summary>
            ///
            /// </summary>
            private readonly Dictionary<string, string> _parameters;

            public RequestHelper(HttpMethod httpMethod, Dictionary<string, string> parameters)
            {
                _httpMethod = httpMethod;
                _parameters = parameters;
            }

            public string _api_access_key { get; } = "3b78a66b1bb04183a0215b7b8e6e18e9";
            public string _api_name { get; } = "hssServives";
            public string _api_timestamp { get; } = "1623325847266";
            public string _api_version { get; } = "1.0.0";
            private void BuildParameters()
            {
                //_parameters.Add(nameof(Format), Format.ToUpper());
                //_parameters.Add(nameof(Version), Version);
                //_parameters.Add(nameof(AccessKeyId), AccessKeyId);
                //_parameters.Add(nameof(SignatureVersion), SignatureVersion);
                //_parameters.Add(nameof(SignatureMethod), SignatureMethod);
                //_parameters.Add(nameof(SignatureNonce), SignatureNonce);
                //_parameters.Add(nameof(Timestamp), Timestamp);
                _parameters.Add(nameof(_api_name), _api_name);
                _parameters.Add(nameof(_api_access_key), Timestamp);
                _parameters.Add(nameof(_api_timestamp), _api_timestamp);
                _parameters.Add(nameof(_api_version), _api_version);
            }

            public void ComputeSignature()
            {
                BuildParameters();
                var canonicalizedQueryString = string.Join("&",
                    _parameters.OrderBy(x => x.Key)
                    .Select(x => PercentEncode(x.Key) + "=" + PercentEncode(x.Value)));
                //.Select(x => x.Key + "=" + x.Value));

                var stringToSign = _httpMethod.ToString().ToUpper() + "&%2F&" + PercentEncode(canonicalizedQueryString);
                //var stringToSign = _httpMethod.ToString().ToUpper() + "&" + PercentEncode(canonicalizedQueryString);

                var keyBytes = Encoding.UTF8.GetBytes(AccessKeySecret + "&");
                var hmac = new HMACSHA1(keyBytes);
                var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
                Signature = Convert.ToBase64String(hashBytes);
                _parameters.Add(nameof(Signature), Signature);
            }

            private string PercentEncode(string value)
            {
                return UpperCaseUrlEncode(value)
                    .Replace("+", "%20")
                    .Replace("*", "%2A")
                    .Replace("%7E", "~");
            }

            private static string UpperCaseUrlEncode(string s)
            {
                char[] temp = HttpUtility.UrlEncode(s).ToCharArray();
                for (int i = 0; i < temp.Length - 2; i++)
                {
                    if (temp[i] == '%')
                    {
                        temp[i + 1] = char.ToUpper(temp[i + 1]);
                        temp[i + 2] = char.ToUpper(temp[i + 2]);
                    }
                }
                return new string(temp);
            }

            public string GetUrl(string url)
            {
                ComputeSignature();
                return "http://" + url + "/?" +
                    string.Join("&", _parameters.Select(x => x.Key + "=" + HttpUtility.UrlEncode(x.Value)));
            }
        }
        static void Main(string[] args)
        {
            String secretKey = "4txZk+mhrU/JMLXmyP5m3S4Rc20=";
            String accessKey = "3b78a66b1bb04183a0215b7b8e6e18e9";
            String timestamp = "1623325847266";
            String version = "1.0.0";
            String service1 = "hssServives";
            String paramsS = "_api_access_key=" + accessKey + "&_api_name=" + service1 + "&_api_timestamp=" + timestamp + "&_api_version=" + version;

            Console.WriteLine(HmacSha1Sign(paramsS, secretKey));
            Console.ReadKey();
        }
        private static async void CheckDomain(string domain = "cdn.aliyuncs.com")
        {
            var parameters = new Dictionary<string, string>()
                {
                    {"Action", "DescribeDomainSrcFlowData"},
                };
            var request = new RequestHelper(HttpMethod.Get, parameters);
            var url = request.GetUrl(domain);
            string result;
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.GetAsync(url);
                result = await response.Content.ReadAsStringAsync();
            }
        }

        public static string HmacSha1Sign(string text, string key)
        {
            Encoding encode = Encoding.GetEncoding("UTF-8");
            byte[] byteData = encode.GetBytes(text);
            byte[] byteKey = encode.GetBytes(key);
            HMACSHA1 hmac = new HMACSHA1(byteKey);
            CryptoStream cs = new CryptoStream(Stream.Null, hmac, CryptoStreamMode.Write);
            cs.Write(byteData, 0, byteData.Length);
            cs.Close();
            return Convert.ToBase64String(hmac.Hash);
        }
    }
}