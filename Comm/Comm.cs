using System.Runtime.InteropServices;

namespace Comm
{
    [ComVisible(true)]
    public interface IWelcome
    {
        [DispId(1)]
        string Greeting(string name);
    }

    [ComVisible(true)]
    public interface IMath
    {
        [DispId(2)]
        int add(int val1, int val2);
        [DispId(3)]
        int sub(int val1, int val2);
        [DispId(4)]
        long HmacSha1Sign(string text, string key, ref string _sign, ref string _error);
        [DispId(5)]
        long PostHttp(string data, string url, string sign, string timestamp, string version, string apiname, string acckey, ref string ls_out);
        [DispId(6)]
        long getEc(string strUrl, string InData, ref string OutData);
        [DispId(7)]
        long init_kxr(string pUrl, string pUser,ref string ls_out);
    }
}
