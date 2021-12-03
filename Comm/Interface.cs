using System;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Net;

namespace Comm
{
    [ComVisible(true)]
    [Guid("C185BACB-4BB7-4FCD-942F-5E9EA5F0F6F7")]
    [ProgId("KxrComm")]
    public class Interface : IWelcome, IMath
    {
        public int add(int val1, int val2)
        {
            return val1 + val2;
        }

        public string Greeting(string name)
        {
            return "Hello " + name;
        }

        public int sub(int val1, int val2)
        {
            return val1 - val2;
        }
        public long HmacSha1Sign(string text, string key, ref string _sign, ref string _error)
        {
            try
            {
                Encoding encode = Encoding.GetEncoding("UTF-8");
                byte[] byteData = encode.GetBytes(text);
                byte[] byteKey = encode.GetBytes(key);
                HMACSHA1 hmac = new HMACSHA1(byteKey);
                CryptoStream cs = new CryptoStream(Stream.Null, hmac, CryptoStreamMode.Write);
                cs.Write(byteData, 0, byteData.Length);
                cs.Close();
                _sign = Convert.ToBase64String(hmac.Hash);
            }
            catch(Exception ex)
            {
                _error = ex.Message.ToString();
                return -1;
            }
            return 1;
        }

        [DllImport("SSCard.dll")]
        public static extern int NationEcTrans(string strUrl, string InData, ref string OutData);
        [DllImport("SSCard.dll")]
        public static extern int Init(string pUrl, string pUser);
        public long getEc(string url, string indata, ref string outdata)
        {
            long ll_ret = -1;
            try
            {
                ll_ret = NationEcTrans(url, indata, ref outdata);
                return ll_ret;
            }
            catch (Exception ex)
            {
                outdata = ex.Message.ToString();
                return -1;
            }

        }
        public long init_kxr(string pUrl, string pUser, ref string ls_out)
        {
            long ll_ret = -1;
            try
            {
                ll_ret = Init(pUrl, pUser);
                return ll_ret;
            }
            catch (Exception ex)
            {
                ls_out = ex.Message.ToString();
                return -1;
            }

        }
        public long PostHttp(string data,string url, string sign, string timestamp, string version, string apiname, string acckey, ref string ls_out)
        {
            try
            {
                Encoding myEncoding = Encoding.GetEncoding("utf-8");  //选择编码字符集
                byte[] bytesToPost = System.Text.Encoding.Default.GetBytes(data); //转换为bytes数据

                string responseResult = String.Empty;
                HttpWebRequest req = (HttpWebRequest)
                HttpWebRequest.Create(url);   //创建一个有效的httprequest请求，地址和端口和指定路径必须要和网页系统工程师确认正确，不然一直通讯不成功
                req.Method = "POST";
                req.ContentType = "application/json";
                req.ContentLength = bytesToPost.Length;
                req.ProtocolVersion = HttpVersion.Version10;
                req.Headers.Add("_api_signature", sign);
                req.Headers.Add("_api_timestamp", timestamp);
                req.Headers.Add("_api_version", version);
                req.Headers.Add("_api_access_key", acckey);
                req.Headers.Add("_api_name", apiname);
                using (Stream reqStream = req.GetRequestStream())
                {
                    reqStream.Write(bytesToPost, 0, bytesToPost.Length);     //把要上传网页系统的数据通过post发送
                }
                HttpWebResponse cnblogsRespone = (HttpWebResponse)req.GetResponse();
                if (cnblogsRespone != null && cnblogsRespone.StatusCode == HttpStatusCode.OK)
                {
                    StreamReader sr;
                    using (sr = new StreamReader(cnblogsRespone.GetResponseStream()))
                    {
                        responseResult = sr.ReadToEnd();  //网页系统的json格式的返回值，在responseResult里，具体内容就是网页系统负责工程师跟你协议号的返回值协议内容
                    }
                    sr.Close();
                }
                cnblogsRespone.Close();
                ls_out = responseResult;
                return 1;
            }
            catch(Exception ex)
            {
                ls_out = ex.Message.ToString();
                return 0;
            }
        }
    }
}
