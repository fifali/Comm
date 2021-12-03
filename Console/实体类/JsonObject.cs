using System.Runtime.Serialization;
namespace ConsoleHydee
{
    [DataContract]
    #region 测试
    #region 返回体头-Test
    public class RetHead_TestJson
    {
        [DataMember(Order = 0)]
        public string carname { get; set; }

        [DataMember(Order = 1)]
        public int controltype { get; set; }

        [DataMember(Order = 2)]
        public int ifbody { get; set; }

        [DataMember(Order = 3)]
        public int rownum { get; set; }
    }
    #endregion
    #region 返回体尾-Body1
    public class RetBody_TestJson
    {
        [DataMember(Order = 0)]
        public string color { get; set; }

        [DataMember(Order = 1)]
        public int? price { get; set; }
    }
    #endregion
    #region 返回体尾-Body2
    public class RetBody_Test2Json
    {
        [DataMember(Order = 0)]
        public string car { get; set; }

        [DataMember(Order = 1)]
        public int? size { get; set; }
    }
    #endregion
    #endregion
    #region 请求消息
    public class ReqHeadJson
    {
        [DataMember(Order = 0)]
        public string functionid { get; set; }

        [DataMember(Order = 1)]
        public string orgcode { get; set; }

        [DataMember(Order = 2)]
        public string interfaces { get; set; }

        [DataMember(Order = 3)]
        public string sendtext { get; set; }

        [DataMember(Order = 4)]
        public string param1 { get; set; }

        [DataMember(Order = 5)]
        public string param2 { get; set; }

        [DataMember(Order = 6)]
        public string param3 { get; set; }

        [DataMember(Order = 7)]
        public string param4 { get; set; }

        [DataMember(Order = 8)]
        public string param5 { get; set; }
    }
    #endregion

    #region 返回消息
    public class RetHeadJson
    {
        [DataMember(Order = 0)]
        public string functionid { get; set; }

        [DataMember(Order = 1)]
        public string returncode { get; set; }

        [DataMember(Order = 2)]
        public string returnmsg { get; set; }
    }
    #endregion

    #region 请求体头
    public class ReqBodyHeadJson
    {
        [DataMember(Order = 0)]
        public int? type { get; set; }
        [DataMember(Order = 1)]
        public string find1 { get; set; }
        [DataMember(Order = 2)]
        public string find2 { get; set; }
        [DataMember(Order = 3)]
        public string find3 { get; set; }
        [DataMember(Order = 4)]
        public string find4 { get; set; }
        [DataMember(Order = 5)]
        public string find5 { get; set; }
        [DataMember(Order = 6)]
        public string carname { get; set; }
        [DataMember(Order = 7)]
        public string code { get; set; }
        [DataMember(Order = 8)]
        public string name { get; set; }
        [DataMember(Order = 9)]
        public string guid { get; set; }
    }
    #endregion

    #region 返回体头
    public class RetBodyHeadJson
    {
        [DataMember(Order = 0)]
        public string carname { get; set; }
        [DataMember(Order = 1)]
        public int? controltype { get; set; }
        [DataMember(Order = 2)]
        public int? ifbody { get; set; }
        [DataMember(Order = 3)]
        public string userguid { get; set; }
        [DataMember(Order = 4)]
        public string username { get; set; }
        [DataMember(Order = 5)]
        public string userpower { get; set; }
        [DataMember(Order = 6)]
        public string orgguid { get; set; }
        [DataMember(Order = 7)]
        public string orgname { get; set; }
        [DataMember(Order = 8)]
        public string cardguid { get; set; }
        [DataMember(Order = 9)]
        public string cardname { get; set; }
        [DataMember(Order = 10)]
        public string usercode { get; set; }
        [DataMember(Order = 11)]
        public int? flag { get; set; }
    }
    #endregion

    #region 返回体尾-汽车分类
    public class RetBody_CartypeJson
    {
        [DataMember(Order = 0)]
        public string carname { get; set; }
    }
    #endregion

    #region 返回体尾-未来价值
    public class RetBody_WljzJson
    {
        [DataMember(Order = 0)]
        public string jdy { get; set; }

        [DataMember(Order = 1)]
        public int? ngzl { get; set; }

        [DataMember(Order = 2)]
        public int? kyzl { get; set; }

        [DataMember(Order = 3)]
        public int? ndzl { get; set; }

        [DataMember(Order = 4)]
        public int? qlzl { get; set; }

        [DataMember(Order = 5)]
        public int? zj { get; set; }
    }
    #endregion

    #region 返回体尾-历史价值
    public class RetBody_LsjzJson
    {
        [DataMember(Order = 0)]
        public string jdy { get; set; }
        [DataMember(Order = 1)]
        public int? xybc { get; set; }
        [DataMember(Order = 2)]
        public int? ybfz { get; set; }
        [DataMember(Order = 3)]
        public int? ybjz { get; set; }
        [DataMember(Order = 4)]
        public int? ybwl { get; set; }
        [DataMember(Order = 5)]
        public int? zybc { get; set; }
        [DataMember(Order = 6)]
        public int? zyfz { get; set; }
        [DataMember(Order = 7)]
        public int? zyjz { get; set; }
        [DataMember(Order = 8)]
        public int? zywl { get; set; }
        [DataMember(Order = 9)]
        public int? zj { get; set; }
    }
    #endregion

    #region 返回体尾-综合价值
    public class RetBody_ZhjzJson
    {
        [DataMember(Order = 0)]
        public string lsjz { get; set; }

        [DataMember(Order = 1)]
        public int? ngzl { get; set; }

        [DataMember(Order = 2)]
        public int? kyzl { get; set; }

        [DataMember(Order = 3)]
        public int? ndzl { get; set; }

        [DataMember(Order = 4)]
        public int? qlzl { get; set; }

        [DataMember(Order = 5)]
        public int? zj { get; set; }
    }
    #endregion

    #region 返回体尾-数据明细
    public class RetBody_DetailJson
    {
        [DataMember(Order = 0)]
        public string car { get; set; }
        [DataMember(Order = 1)]
        public string dph { get; set; }
        [DataMember(Order = 2)]
        public string hyd { get; set; }
        [DataMember(Order = 3)]
        public decimal? pc { get; set; }
        [DataMember(Order = 4)]
        public decimal? jsje { get; set; }
        [DataMember(Order = 5)]
        public string jsrq { get; set; }
        [DataMember(Order = 6)]
        public decimal? kdj { get; set; }
        [DataMember(Order = 7)]
        public decimal? jgts { get; set; }
        [DataMember(Order = 8)]
        public decimal? gcts { get; set; }
        [DataMember(Order = 9)]
        public decimal? cl { get; set; }
        [DataMember(Order = 10)]
        public decimal? zhlc { get; set; }
        [DataMember(Order = 11)]
        public string gmrq { get; set; }
        [DataMember(Order = 12)]
        public string wxlb { get; set; }
        [DataMember(Order = 13)]
        public string jdy { get; set; }
        [DataMember(Order = 14)]
        public string scrq { get; set; }
        [DataMember(Order = 15)]
        public string lsjz { get; set; }
        [DataMember(Order = 16)]
        public string wljz { get; set; }
        [DataMember(Order = 17)]
        public string ldkhqjlb { get; set; }
        [DataMember(Order = 18)]
        public string kdjqjlb { get; set; }
        [DataMember(Order = 19)]
        public string whdqjlb { get; set; }
        [DataMember(Order = 20)]
        public string qlqjlb { get; set; }
        [DataMember(Order = 21)]
        public decimal? gchzlc { get; set; }
        [DataMember(Order = 22)]
        public string escqjlb { get; set; }
    }
    #endregion

    #region PB自动生成
    public class tb_hydee_add
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string addguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string objectguid { get; set; }
        [DataMember(Order = 3)]
        public string addtype { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_baseinfo
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string platguid { get; set; }
        [DataMember(Order = 1)]
        public string platname { get; set; }
        [DataMember(Order = 2)]
        public string platadd { get; set; }
        [DataMember(Order = 3)]
        public string platpeoper { get; set; }
        [DataMember(Order = 4)]
        public string plattel { get; set; }
        [DataMember(Order = 5)]
        public string platicons { get; set; }
        [DataMember(Order = 6)]
        public string webservices { get; set; }
        [DataMember(Order = 7)]
        public string operuser { get; set; }
        [DataMember(Order = 8)]
        public string operdate { get; set; }
        [DataMember(Order = 9)]
        public string remark { get; set; }
    }
    public class tb_hydee_card
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string cardguid { get; set; }
        [DataMember(Order = 1)]
        public string cardcode { get; set; }
        [DataMember(Order = 2)]
        public string cardname { get; set; }
        [DataMember(Order = 3)]
        public string groupname { get; set; }
        [DataMember(Order = 4)]
        public string natures { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_charptertype
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string typeguid { get; set; }
        [DataMember(Order = 1)]
        public string typecode { get; set; }
        [DataMember(Order = 2)]
        public string typename { get; set; }
        [DataMember(Order = 3)]
        public string operuser { get; set; }
        [DataMember(Order = 4)]
        public string operdate { get; set; }
        [DataMember(Order = 5)]
        public string remark { get; set; }
    }
    public class tb_hydee_company
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string companyguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string companycode { get; set; }
        [DataMember(Order = 3)]
        public string companyname { get; set; }
        [DataMember(Order = 4)]
        public string companyadd { get; set; }
        [DataMember(Order = 5)]
        public string companyowner { get; set; }
        [DataMember(Order = 6)]
        public string tels { get; set; }
        [DataMember(Order = 7)]
        public string persons { get; set; }
        [DataMember(Order = 8)]
        public string operuser { get; set; }
        [DataMember(Order = 9)]
        public string operdate { get; set; }
        [DataMember(Order = 10)]
        public string remark { get; set; }
        [DataMember(Order = 11)]
        public int? orderno { get; set; }
        [DataMember(Order = 12)]
        public string status { get; set; }
    }
    public class tb_hydee_companyaut
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string recordguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string applydate { get; set; }
        [DataMember(Order = 3)]
        public string applytype { get; set; }
        [DataMember(Order = 4)]
        public string checkpeoper { get; set; }
        [DataMember(Order = 5)]
        public string checkdate { get; set; }
        [DataMember(Order = 6)]
        public string checkstatus { get; set; }
        [DataMember(Order = 7)]
        public string checksug { get; set; }
        [DataMember(Order = 8)]
        public string operuser { get; set; }
        [DataMember(Order = 9)]
        public string operdate { get; set; }
        [DataMember(Order = 10)]
        public string remark { get; set; }
    }
    public class tb_hydee_companycard
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string companycardguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string cardguid { get; set; }
        [DataMember(Order = 3)]
        public string cardpath { get; set; }
        [DataMember(Order = 4)]
        public string status { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_companychapter
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string chapterguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string typeguid { get; set; }
        [DataMember(Order = 3)]
        public string chapterpath { get; set; }
        [DataMember(Order = 4)]
        public string status { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_companycoin
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string companycoinguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public decimal? coinnum { get; set; }
        [DataMember(Order = 3)]
        public string operuser { get; set; }
        [DataMember(Order = 4)]
        public string operdate { get; set; }
        [DataMember(Order = 5)]
        public string remark { get; set; }
    }
    public class tb_hydee_companycoinin
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string inguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string ruleguid { get; set; }
        [DataMember(Order = 3)]
        public decimal? inmoney { get; set; }
        [DataMember(Order = 4)]
        public string intype { get; set; }
        [DataMember(Order = 5)]
        public decimal? addnum { get; set; }
        [DataMember(Order = 6)]
        public decimal? havenum { get; set; }
        [DataMember(Order = 7)]
        public string operuser { get; set; }
        [DataMember(Order = 8)]
        public string operdate { get; set; }
        [DataMember(Order = 9)]
        public string remark { get; set; }
    }
    public class tb_hydee_companycoinout
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string outguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string roleguid { get; set; }
        [DataMember(Order = 3)]
        public string outtype { get; set; }
        [DataMember(Order = 4)]
        public decimal? delnum { get; set; }
        [DataMember(Order = 5)]
        public decimal? havenum { get; set; }
        [DataMember(Order = 6)]
        public string operuser { get; set; }
        [DataMember(Order = 7)]
        public string operdate { get; set; }
        [DataMember(Order = 8)]
        public string remark { get; set; }
    }
    public class tb_hydee_companyctrmode
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string modeguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string modename { get; set; }
        [DataMember(Order = 3)]
        public string modepath { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_companyctrtype
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string typeguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string typecode { get; set; }
        [DataMember(Order = 3)]
        public string typename { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_companyinit
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string initguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string operuser { get; set; }
        [DataMember(Order = 3)]
        public string operdate { get; set; }
        [DataMember(Order = 4)]
        public string remark { get; set; }
    }
    public class tb_hydee_companynote
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string noteguid { get; set; }
        [DataMember(Order = 1)]
        public string securguid { get; set; }
        [DataMember(Order = 2)]
        public string userguid { get; set; }
        [DataMember(Order = 3)]
        public string sendmsg { get; set; }
        [DataMember(Order = 4)]
        public string status { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_companysecur
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string securguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string userguid { get; set; }
        [DataMember(Order = 3)]
        public string contralguid { get; set; }
        [DataMember(Order = 4)]
        public string workguid { get; set; }
        [DataMember(Order = 5)]
        public string chapterguid { get; set; }
        [DataMember(Order = 6)]
        public string natures { get; set; }
        [DataMember(Order = 7)]
        public string opertype { get; set; }
        [DataMember(Order = 8)]
        public decimal? orderno { get; set; }
        [DataMember(Order = 9)]
        public string operuser { get; set; }
        [DataMember(Order = 10)]
        public string operdate { get; set; }
        [DataMember(Order = 11)]
        public string remark { get; set; }
    }
    public class tb_hydee_companysecurdetail
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string detailguid { get; set; }
        [DataMember(Order = 1)]
        public string securguid { get; set; }
        [DataMember(Order = 2)]
        public string companycardguid { get; set; }
        [DataMember(Order = 3)]
        public decimal? orderno { get; set; }
        [DataMember(Order = 4)]
        public string sn { get; set; }
        [DataMember(Order = 5)]
        public string paths { get; set; }
        [DataMember(Order = 6)]
        public string operuser { get; set; }
        [DataMember(Order = 7)]
        public string operdate { get; set; }
        [DataMember(Order = 8)]
        public string remark { get; set; }
    }
    public class tb_hydee_companywork
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string companyworkguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string companyguid { get; set; }
        [DataMember(Order = 3)]
        public string workguid { get; set; }
        [DataMember(Order = 4)]
        public string paths { get; set; }
        [DataMember(Order = 5)]
        public string sn { get; set; }
        [DataMember(Order = 6)]
        public string operuser { get; set; }
        [DataMember(Order = 7)]
        public string operdate { get; set; }
        [DataMember(Order = 8)]
        public string remark { get; set; }
    }
    public class tb_hydee_consrule
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string ruelguid { get; set; }
        [DataMember(Order = 1)]
        public string constype { get; set; }
        [DataMember(Order = 2)]
        public decimal? conscoin { get; set; }
        [DataMember(Order = 3)]
        public string operuser { get; set; }
        [DataMember(Order = 4)]
        public string operdate { get; set; }
        [DataMember(Order = 5)]
        public string remark { get; set; }
    }
    public class tb_hydee_contral
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string contralguid { get; set; }
        [DataMember(Order = 1)]
        public string ctrcode { get; set; }
        [DataMember(Order = 2)]
        public string ctrname { get; set; }
        [DataMember(Order = 3)]
        public string sn { get; set; }
        [DataMember(Order = 4)]
        public string paths { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_contraldetail
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string detailguid { get; set; }
        [DataMember(Order = 1)]
        public string contralguid { get; set; }
        [DataMember(Order = 2)]
        public string userguid { get; set; }
        [DataMember(Order = 3)]
        public string companyguid { get; set; }
        [DataMember(Order = 4)]
        public string typeguid { get; set; }
        [DataMember(Order = 5)]
        public string sn { get; set; }
        [DataMember(Order = 6)]
        public string nature { get; set; }
        [DataMember(Order = 7)]
        public string companynatures { get; set; }
        [DataMember(Order = 8)]
        public string operuser { get; set; }
        [DataMember(Order = 9)]
        public string operdate { get; set; }
        [DataMember(Order = 10)]
        public string remark { get; set; }
    }
    public class tb_hydee_contralpower
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string powerguid { get; set; }
        [DataMember(Order = 1)]
        public string contralguid { get; set; }
        [DataMember(Order = 2)]
        public string userguid { get; set; }
        [DataMember(Order = 3)]
        public string powerdate { get; set; }
        [DataMember(Order = 4)]
        public string powersn { get; set; }
        [DataMember(Order = 5)]
        public decimal? powernum { get; set; }
        [DataMember(Order = 6)]
        public string operuser { get; set; }
        [DataMember(Order = 7)]
        public string operdate { get; set; }
        [DataMember(Order = 8)]
        public string remark { get; set; }
    }
    public class tb_hydee_naturechangeset
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string setguid { get; set; }
        [DataMember(Order = 1)]
        public string detailguid { get; set; }
        [DataMember(Order = 2)]
        public string contralguid { get; set; }
        [DataMember(Order = 3)]
        public string types { get; set; }
        [DataMember(Order = 4)]
        public string changeday { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_note
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string noteguid { get; set; }
        [DataMember(Order = 1)]
        public string securguid { get; set; }
        [DataMember(Order = 2)]
        public string userguid { get; set; }
        [DataMember(Order = 3)]
        public string sendmsg { get; set; }
        [DataMember(Order = 4)]
        public string status { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_operchapter
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string applyguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string contralguid { get; set; }
        [DataMember(Order = 3)]
        public string applyuserguid { get; set; }
        [DataMember(Order = 4)]
        public string checkuserguid { get; set; }
        [DataMember(Order = 5)]
        public string applydate { get; set; }
        [DataMember(Order = 6)]
        public string checkdate { get; set; }
        [DataMember(Order = 7)]
        public string checkmsg { get; set; }
        [DataMember(Order = 8)]
        public string status { get; set; }
        [DataMember(Order = 9)]
        public string operuser { get; set; }
        [DataMember(Order = 10)]
        public string operdate { get; set; }
        [DataMember(Order = 11)]
        public string remark { get; set; }
    }
    public class tb_hydee_param
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string paramguid { get; set; }
        [DataMember(Order = 1)]
        public string paramcode { get; set; }
        [DataMember(Order = 2)]
        public string paramname { get; set; }
        [DataMember(Order = 3)]
        public string paramvalues { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_power
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string powerguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string chapterguid { get; set; }
        [DataMember(Order = 3)]
        public decimal? parentid { get; set; }
        [DataMember(Order = 4)]
        public string natures { get; set; }
        [DataMember(Order = 5)]
        public string parent_ids { get; set; }
        [DataMember(Order = 6)]
        public string powername { get; set; }
        [DataMember(Order = 7)]
        public decimal? sortno { get; set; }
        [DataMember(Order = 8)]
        public string href { get; set; }
        [DataMember(Order = 9)]
        public string target { get; set; }
        [DataMember(Order = 10)]
        public string icon { get; set; }
        [DataMember(Order = 11)]
        public string ifview { get; set; }
        [DataMember(Order = 12)]
        public decimal? height { get; set; }
        [DataMember(Order = 13)]
        public string authorities { get; set; }
        [DataMember(Order = 14)]
        public string operuser { get; set; }
        [DataMember(Order = 15)]
        public string operdate { get; set; }
        [DataMember(Order = 16)]
        public string remark { get; set; }
    }
    public class tb_hydee_rechargerule
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string ruleguid { get; set; }
        [DataMember(Order = 1)]
        public string rechargetype { get; set; }
        [DataMember(Order = 2)]
        public decimal? rechargecoin { get; set; }
        [DataMember(Order = 3)]
        public string operuser { get; set; }
        [DataMember(Order = 4)]
        public string operdate { get; set; }
        [DataMember(Order = 5)]
        public string remark { get; set; }
    }
    public class tb_hydee_sn
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string snguid { get; set; }
        [DataMember(Order = 1)]
        public string sn { get; set; }
        [DataMember(Order = 2)]
        public string operuser { get; set; }
        [DataMember(Order = 3)]
        public string operdate { get; set; }
        [DataMember(Order = 4)]
        public string remark { get; set; }
    }
    public class tb_hydee_telcheck
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string checkguid { get; set; }
        [DataMember(Order = 1)]
        public string tels { get; set; }
        [DataMember(Order = 2)]
        public string checkcode { get; set; }
        [DataMember(Order = 3)]
        public string outdate { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_user
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string userguid { get; set; }
        [DataMember(Order = 1)]
        public string typeguid { get; set; }
        [DataMember(Order = 2)]
        public string usercode { get; set; }
        [DataMember(Order = 3)]
        public string username { get; set; }
        [DataMember(Order = 4)]
        public string loginname { get; set; }
        [DataMember(Order = 5)]
        public string usersex { get; set; }
        [DataMember(Order = 6)]
        public string userpass { get; set; }
        [DataMember(Order = 7)]
        public decimal? ages { get; set; }
        [DataMember(Order = 8)]
        public string cardno { get; set; }
        [DataMember(Order = 9)]
        public string births { get; set; }
        [DataMember(Order = 10)]
        public string tels { get; set; }
        [DataMember(Order = 11)]
        public string email { get; set; }
        [DataMember(Order = 12)]
        public string status { get; set; }
        [DataMember(Order = 13)]
        public string operuser { get; set; }
        [DataMember(Order = 14)]
        public string operdate { get; set; }
        [DataMember(Order = 15)]
        public string remark { get; set; }
        [DataMember(Order = 16)]
        public int? orderno { get; set; }
    }
    public class tb_hydee_useraut
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string recordguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string applydate { get; set; }
        [DataMember(Order = 3)]
        public string applytype { get; set; }
        [DataMember(Order = 4)]
        public string checkpeoper { get; set; }
        [DataMember(Order = 5)]
        public string checkdate { get; set; }
        [DataMember(Order = 6)]
        public string checkstatus { get; set; }
        [DataMember(Order = 7)]
        public string checksug { get; set; }
        [DataMember(Order = 8)]
        public string operuser { get; set; }
        [DataMember(Order = 9)]
        public string operdate { get; set; }
        [DataMember(Order = 10)]
        public string remark { get; set; }
    }
    public class tb_hydee_usercard
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string usercardguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string cardguid { get; set; }
        [DataMember(Order = 3)]
        public string cardpath { get; set; }
        [DataMember(Order = 4)]
        public string status { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
        [DataMember(Order = 8)]
        public string cardbyte { get; set; }
    }
    public class tb_hydee_userchapter
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string chapterguid { get; set; }
        [DataMember(Order = 1)]
        public string typeguid { get; set; }
        [DataMember(Order = 2)]
        public string userguid { get; set; }
        [DataMember(Order = 3)]
        public string chapterpath { get; set; }
        [DataMember(Order = 4)]
        public string status { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_usercoin
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string usercoinguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public decimal? coinnum { get; set; }
        [DataMember(Order = 3)]
        public string operuser { get; set; }
        [DataMember(Order = 4)]
        public string operdate { get; set; }
        [DataMember(Order = 5)]
        public string remark { get; set; }
    }
    public class tb_hydee_usercoinin
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string inguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string ruleguid { get; set; }
        [DataMember(Order = 3)]
        public decimal? inmoney { get; set; }
        [DataMember(Order = 4)]
        public string intype { get; set; }
        [DataMember(Order = 5)]
        public decimal? addnum { get; set; }
        [DataMember(Order = 6)]
        public decimal? havenum { get; set; }
        [DataMember(Order = 7)]
        public string operuser { get; set; }
        [DataMember(Order = 8)]
        public string operdate { get; set; }
        [DataMember(Order = 9)]
        public string remark { get; set; }
    }
    public class tb_hydee_usercoinout
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string outguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string roleguid { get; set; }
        [DataMember(Order = 3)]
        public string outtype { get; set; }
        [DataMember(Order = 4)]
        public decimal? delnum { get; set; }
        [DataMember(Order = 5)]
        public decimal? havenum { get; set; }
        [DataMember(Order = 6)]
        public string operuser { get; set; }
        [DataMember(Order = 7)]
        public string operdate { get; set; }
        [DataMember(Order = 8)]
        public string remark { get; set; }
    }
    public class tb_hydee_usercompany
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string usercompanyguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string companyguid { get; set; }
        [DataMember(Order = 3)]
        public string natures { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_userctrmode
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string modeguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string modename { get; set; }
        [DataMember(Order = 3)]
        public string modepath { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_userctrtype
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string typeguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string typecode { get; set; }
        [DataMember(Order = 3)]
        public string typename { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_userfind
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string findguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string checkuser { get; set; }
        [DataMember(Order = 3)]
        public string finddate { get; set; }
        [DataMember(Order = 4)]
        public string findtype { get; set; }
        [DataMember(Order = 5)]
        public string findsn { get; set; }
        [DataMember(Order = 6)]
        public string checkdate { get; set; }
        [DataMember(Order = 7)]
        public string checksug { get; set; }
        [DataMember(Order = 8)]
        public string status { get; set; }
        [DataMember(Order = 9)]
        public string operuser { get; set; }
        [DataMember(Order = 10)]
        public string operdate { get; set; }
        [DataMember(Order = 11)]
        public string remark { get; set; }
    }
    public class tb_hydee_userpower
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string userpowerguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string companyguid { get; set; }
        [DataMember(Order = 3)]
        public string powerguid { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class tb_hydee_usersecur
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string securguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string contralguid { get; set; }
        [DataMember(Order = 3)]
        public string workguid { get; set; }
        [DataMember(Order = 4)]
        public string chapterguid { get; set; }
        [DataMember(Order = 5)]
        public string natures { get; set; }
        [DataMember(Order = 6)]
        public string opertype { get; set; }
        [DataMember(Order = 7)]
        public decimal? orderno { get; set; }
        [DataMember(Order = 8)]
        public string operuser { get; set; }
        [DataMember(Order = 9)]
        public string operdate { get; set; }
        [DataMember(Order = 10)]
        public string remark { get; set; }
    }
    public class tb_hydee_usersecurdetail
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string detailguid { get; set; }
        [DataMember(Order = 1)]
        public string securguid { get; set; }
        [DataMember(Order = 2)]
        public string usercardguid { get; set; }
        [DataMember(Order = 3)]
        public decimal? orderno { get; set; }
        [DataMember(Order = 4)]
        public string sn { get; set; }
        [DataMember(Order = 5)]
        public string paths { get; set; }
        [DataMember(Order = 6)]
        public string operuser { get; set; }
        [DataMember(Order = 7)]
        public string operdate { get; set; }
        [DataMember(Order = 8)]
        public string remark { get; set; }
    }
    public class tb_hydee_usersign
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string signguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string signname { get; set; }
        [DataMember(Order = 3)]
        public string signpath { get; set; }
        [DataMember(Order = 4)]
        public string status { get; set; }
        [DataMember(Order = 5)]
        public string operuser { get; set; }
        [DataMember(Order = 6)]
        public string operdate { get; set; }
        [DataMember(Order = 7)]
        public string remark { get; set; }
    }
    public class tb_hydee_usertype
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string typeguid { get; set; }
        [DataMember(Order = 1)]
        public string typecode { get; set; }
        [DataMember(Order = 2)]
        public string typename { get; set; }
        [DataMember(Order = 3)]
        public string operuser { get; set; }
        [DataMember(Order = 4)]
        public string operdate { get; set; }
        [DataMember(Order = 5)]
        public string remark { get; set; }
    }
    public class tb_hydee_userwork
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string userworkguid { get; set; }
        [DataMember(Order = 1)]
        public string userguid { get; set; }
        [DataMember(Order = 2)]
        public string workguid { get; set; }
        [DataMember(Order = 3)]
        public string paths { get; set; }
        [DataMember(Order = 4)]
        public string sn { get; set; }
        [DataMember(Order = 5)]
        public string status { get; set; }
        [DataMember(Order = 6)]
        public string operuser { get; set; }
        [DataMember(Order = 7)]
        public string operdate { get; set; }
        [DataMember(Order = 8)]
        public string remark { get; set; }
    }
    public class tb_hydee_workdetail
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string detailguid { get; set; }
        [DataMember(Order = 1)]
        public string typeguid { get; set; }
        [DataMember(Order = 2)]
        public string cardguid { get; set; }
        [DataMember(Order = 3)]
        public string operuser { get; set; }
        [DataMember(Order = 4)]
        public string operdate { get; set; }
        [DataMember(Order = 5)]
        public string remark { get; set; }
    }
    public class tb_hydee_workrelease
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string workguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string typeguid { get; set; }
        [DataMember(Order = 3)]
        public string releasedate { get; set; }
        [DataMember(Order = 4)]
        public string releaseuser { get; set; }
        [DataMember(Order = 5)]
        public string status { get; set; }
        [DataMember(Order = 6)]
        public string operuser { get; set; }
        [DataMember(Order = 7)]
        public string operdate { get; set; }
        [DataMember(Order = 8)]
        public string remark { get; set; }
    }
    public class tb_hydee_worktype
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string typeguid { get; set; }
        [DataMember(Order = 1)]
        public string companyguid { get; set; }
        [DataMember(Order = 2)]
        public string typecode { get; set; }
        [DataMember(Order = 3)]
        public string typename { get; set; }
        [DataMember(Order = 4)]
        public string operuser { get; set; }
        [DataMember(Order = 5)]
        public string operdate { get; set; }
        [DataMember(Order = 6)]
        public string remark { get; set; }
    }
    public class interface_gjzh_fkmsk
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string merId { get; set; }
        [DataMember(Order = 1)]
        public string subAppId { get; set; }
        [DataMember(Order = 2)]
        public string orderId { get; set; }
        [DataMember(Order = 3)]
        public string authCode { get; set; }
        [DataMember(Order = 4)]
        public string userId { get; set; }
        [DataMember(Order = 5)]
        public string termId { get; set; }
        [DataMember(Order = 6)]
        public string notifyUrl { get; set; }
        [DataMember(Order = 7)]
        public string txnAmt { get; set; }
        [DataMember(Order = 8)]
        public string currencyCode { get; set; }
        [DataMember(Order = 9)]
        public string body { get; set; }
        [DataMember(Order = 10)]
        public string mchReserved { get; set; }
        [DataMember(Order = 11)]
        public string tradeScene { get; set; }
        [DataMember(Order = 12)]
        public string identity { get; set; }
        [DataMember(Order = 13)]
        public string policyNo { get; set; }
    }
    public class interface_gjzh_fkmsk_ret
    {
        [DataMember(Order = 0, IsRequired = true)]
        public string cmborderid { get; set; }
        [DataMember(Order = 1)]
        public string txnamt { get; set; }
        [DataMember(Order = 2)]
        public string dscamt { get; set; }
        [DataMember(Order = 3)]
        public string paytype { get; set; }
        [DataMember(Order = 4)]
        public string openid { get; set; }
        [DataMember(Order = 5)]
        public string tradestate { get; set; }
        [DataMember(Order = 6)]
        public string txntime { get; set; }
        [DataMember(Order = 7)]
        public string enddate { get; set; }
        [DataMember(Order = 8)]
        public string endtime { get; set; }
        [DataMember(Order = 9)]
        public string orderid { get; set; }
        [DataMember(Order = 10)]
        public string merid { get; set; }
    }
    #endregion
}