using System;
using System.Data;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using System.Configuration;
using System.Net;
using System.Text;
using swiftpass.utils;
namespace ConsoleHydee
{
    class Program
    {
        static HttpListener httpobj;

        static void Main(string[] args)
        {
            Console.WriteLine("");
            PublicBll bll = new PublicBll();
            //提供一个简单的、可通过编程方式控制的 HTTP 协议侦听器。此类不能被继承。
            httpobj = new HttpListener();
            //定义url及端口号，通常设置为配置文件
            //string url = ConfigurationManager.AppSettings["Url"];
            string url = "";
            bll.geturlParms(Environment.CurrentDirectory + "\\DBConn\\001.xml", out url);
            Console.WriteLine($"URL：{url}\r\n");
            httpobj.Prefixes.Add(url);
            //启动监听器
            httpobj.Start();
            //异步监听客户端请求，当客户端的网络请求到来时会自动执行Result委托
            //该委托没有返回值，有一个IAsyncResult接口的参数，可通过该参数获取context对象
            httpobj.BeginGetContext(Result, null);
            Console.WriteLine($"服务端初始化完毕，正在等待客户端请求,版本2.0.1时间：{DateTime.Now.ToString()}\r\n");
            Console.ReadKey();
        }

        private static void Result(IAsyncResult ar)
        {
            //当接收到请求后程序流会走到这里

            //继续异步监听
            httpobj.BeginGetContext(Result, null);
            var guid = Guid.NewGuid().ToString();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"接到新的请求:{guid},时间：{DateTime.Now.ToString()}\r\n");
            //获得context对象
            var context = httpobj.EndGetContext(ar);
            var request = context.Request;
            var response = context.Response;
            ////如果是js的ajax请求，还可以设置跨域的ip地址与参数
            //context.Response.AppendHeader("Access-Control-Allow-Origin", "*");//后台跨域请求，通常设置为配置文件
            //context.Response.AppendHeader("Access-Control-Allow-Headers", "ID,PW");//后台跨域参数设置，通常设置为配置文件
            //context.Response.AppendHeader("Access-Control-Allow-Method", "post");//后台跨域请求设置，通常设置为配置文件
            context.Response.ContentType = "text/plain;charset=UTF-8";//告诉客户端返回的ContentType类型为纯文本格式，编码为UTF-8
            context.Response.AddHeader("Content-type", "text/plain");//添加响应头信息
            context.Response.ContentEncoding = Encoding.UTF8;
            string returnObj = null;//定义返回客户端的信息
            if (request.HttpMethod == "POST" && request.InputStream != null)
            {
                //处理客户端发送的请求并返回处理信息
                returnObj = HandleRequest(request, response);
            }
            else
            {
                returnObj = $"不是post请求或者传过来的数据为空\r\n";
            }
            var returnByteArr = Encoding.UTF8.GetBytes(returnObj);//设置客户端返回信息的编码
            try
            {
                using (var stream = response.OutputStream)
                {
                    //把处理信息返回到客户端
                    stream.Write(returnByteArr, 0, returnByteArr.Length);
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"网络蹦了：{ex.ToString()}\r\n");
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"请求处理完成：{guid},时间：{ DateTime.Now.ToString()}\r\n");
        }

        private static string HandleRequest(HttpListenerRequest request, HttpListenerResponse response)
        {
            string data = null;
            string ls_retdata = null;
            string dodata = null;
            try
            {
                var byteList = new List<byte>();
                var byteArr = new byte[2048];
                int readLen = 0;
                int len = 0;
                //接收客户端传过来的数据并转成字符串类型
                do
                {
                    readLen = request.InputStream.Read(byteArr, 0, byteArr.Length);
                    len += readLen;
                    byteList.AddRange(byteArr);
                } while (readLen != 0);
                data = Encoding.UTF8.GetString(byteList.ToArray(), 0, len);
                dodata = HydeeInterfaces(data,ref ls_retdata);
                //获取得到数据data可以进行其他操作
            }
            catch (Exception ex)
            {
                response.StatusDescription = "404";
                response.StatusCode = 404;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"在接收数据时发生错误:{ex.ToString()}\r\n");
                return $"在接收数据时发生错误:{ex.ToString()}\r\n";//把服务端错误信息直接返回可能会导致信息不安全，此处仅供参考
            }
            response.StatusDescription = "200";//获取或设置返回给客户端的 HTTP 状态代码的文本说明。
            response.StatusCode = 200;// 获取或设置返回给客户端的 HTTP 状态代码。
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"接收数据完成:{data.Trim()},时间：{DateTime.Now.ToString()}\r\n");
            //Console.WriteLine($"接收数据:{ls_retdata.Trim()},时间：{DateTime.Now.ToString()}\r\n");
            Console.WriteLine($"数据处理结果：{dodata}\r\n");
            //return $"接收数据完成";
            return dodata;
        }

        public static string HydeeInterfaces(string ReqHeadJson,ref string data)
        {
            #region 变量定义
            string ls_retmsg = "TRUE";
            string ls_cn = null;
            string RetDataJson = "";
            string ls_retJson = "";
            string ls_connect = "";
            string _GetHeadJson = "";
            //string ls_url = "";
            //string ls_appid = "";
            //string ls_appsecret = "";
            string ls_sendtext = "";
            string ls_timestamp = "";
            string ls_apisign = "";
            string ls_postdata = "";
            string ls_param1 = "";
            string ls_param2 = "";
            string ls_param3 = "";
            string ls_param4 = "";
            string ls_param5 = "";
            string ls_biz = "";
            data = "";
            List<ReqHeadJson> _ReqHeadJson;
            PublicBll bll = new PublicBll();
            #endregion
            try
            {
                #region 获取数据库连接
                if (!bll.getcnParms(Environment.CurrentDirectory + "\\DBConn\\" + "002.xml", out ls_connect))
                {
                    return bll.ReturnHead_hydee(false, new List<RetHeadJson>(){
                        new RetHeadJson(){functionid = bll.FunctionId,returncode = "2000",returnmsg = "数据库连接失败:" + ls_connect}
                        }, ReqHeadJson, RetDataJson, ls_postdata, "8", ls_connect);
                }
                ls_cn = ls_connect;
                #endregion
                #region 验证身份
                ls_retJson = bll.checkUserValid_hydee(bll.FunctionId, bll.InterfaceUserID, bll.InterfacePassWord, bll.OperUserID, bll.OperPassWord, ls_connect);
                if (ls_retJson != "TRUE")
                {
                    #region 验证失败返回
                    return bll.ReturnHead_hydee(false, new List<RetHeadJson>(){
                        new RetHeadJson(){functionid = bll.FunctionId,returncode = "2000",returnmsg = ls_retJson}
                        }, ReqHeadJson, RetDataJson, ls_postdata, "8", ls_connect);
                    #endregion
                }
                #endregion
                #region 密匙验证
                //if (bll.Interface != "Hydee")
                //{
                //    if (PublicClass.String2Base64(PublicClass.UserMd5(bll.FunctionId + bll.Opertime)) != bll.Interface)
                //    {
                //        return bll.ReturnHead_hydee(false, new List<RetHeadJson>(){
                //        new RetHeadJson(){functionid = bll.FunctionId,returncode = "2000",returnmsg = "通讯密匙验证失败"}
                //        }, ReqHeadJson, RetDataJson, ls_postdata, "8", ls_connect);
                //    }
                //}
                #endregion
                #region 反序列化请求Head
                var jObject = JObject.Parse(ReqHeadJson);
                if (jObject.Property("Head") == null)
                {
                    #region 找不到Head标签返回
                    return bll.ReturnHead_hydee(false, new List<RetHeadJson>(){
                        new RetHeadJson(){functionid = "",returncode = "2000",returnmsg = "ReqHeadJson字符串中未找到Head标签"}
                        }, ReqHeadJson, RetDataJson, ls_postdata, "8",ls_connect);
                    #endregion
                }
                _GetHeadJson = jObject["Head"].ToString();
                _ReqHeadJson = new List<ReqHeadJson>();
                _ReqHeadJson = PublicClass.JsonStringToList<ReqHeadJson>(_GetHeadJson);
                if (_ReqHeadJson.Count == 0)
                {
                    #region 消息体无内容返回
                    return bll.ReturnHead_hydee(false, new List<RetHeadJson>(){
                        new RetHeadJson(){functionid = "",returncode = "2000",returnmsg = "ReqHeadJson字符串中未找到消息体"}
                        }, ReqHeadJson, RetDataJson, ls_postdata, "8",ls_connect);
                    #endregion
                }
                #endregion
                #region 变量初始化
                bll.Interface = _ReqHeadJson[0].interfaces;
                bll.FunctionId = _ReqHeadJson[0].functionid;
                bll.OrgCode = _ReqHeadJson[0].orgcode;
                ls_sendtext = _ReqHeadJson[0].sendtext;
                ls_param1 = _ReqHeadJson[0].param1;
                ls_param2 = _ReqHeadJson[0].param2;
                ls_param3 = _ReqHeadJson[0].param3;
                ls_param4 = _ReqHeadJson[0].param4;
                ls_param5 = _ReqHeadJson[0].param5;
                #endregion
                switch (bll.FunctionId)
                {
                    case "2001"://付款码收款
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_xyf(ls_sendtext,ls_param1,ls_param2,ls_param3,ls_param4,ls_param5);
                        #endregion
                        break;
                    case "2002"://付款码退款
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_xyf_ret(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "2003"://冲正
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_xyf_cancel(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "2004"://付款码收款查询
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_xyf_find(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "2005"://退款查询
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_xyf_ret_find(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "3001"://亿保收银
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_yb_sy(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "3002"://亿保退费
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_yb_ret(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "3003"://亿保查询余额
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_yb_cxye(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "3004"://亿保询问
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_yb_xw(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "3005"://亿保上传目录
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        ls_retmsg = bll.interface_yb_sc(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    case "4001"://售药机补、退货回调
                        #region 处理
                        ls_timestamp = PublicClass.GetTimeStamp();
                        //ls_sendtext = ls_sendtext.Replace("\\","");
                        ls_retmsg = bll.interface_syj_hd(ls_sendtext, ls_param1, ls_param2, ls_param3, ls_param4, ls_param5);
                        #endregion
                        break;
                    default:
                        ls_retmsg = "无法识别的功能号";
                        break;
                }
                #region 返回
                if (ls_retmsg != "TRUE")
                {
                    #region 错误返回
                    return bll.ReturnHead_hydee(false, new List<RetHeadJson>(){
                        new RetHeadJson(){functionid = bll.FunctionId,returncode = "2000",returnmsg = ls_retmsg}}, ReqHeadJson + '@' + ls_timestamp + '@' + ls_apisign + '@' + ls_biz, RetDataJson, ls_postdata, "8", ls_connect);
                    #endregion
                }
                else
                {
                    #region 成功返回
                    return bll.ReturnHead_hydee(true, new List<RetHeadJson>(){
                        new RetHeadJson(){functionid = bll.FunctionId,returncode = "0000",returnmsg = ls_retmsg}
                        }, ReqHeadJson + '@' + ls_timestamp + '@' + ls_apisign + '@' + ls_biz, RetDataJson, ls_postdata, "8", ls_connect);
                    #endregion
                }
                #endregion
            }
            catch (Exception ex)
            {
                #region 异常返回
                return bll.ReturnHead_hydee(false, new List<RetHeadJson>(){
                        new RetHeadJson() { functionid = bll.FunctionId,returncode = "2000",returnmsg = "出现异常：" + ex.Message.ToString()}
                         }, ReqHeadJson + '@' + ls_timestamp + '@' + ls_apisign + '@' + ls_biz, RetDataJson, ls_postdata, "8",ls_connect);
                #endregion
            }
        }
    }
}
