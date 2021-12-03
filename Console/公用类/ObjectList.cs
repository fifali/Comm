using System.Collections.Generic;
namespace ConsoleHydee
{
    public class ObjectList
    {
        #region 返回消息
        public class RetHeadJsonList
        {
            public List<RetHeadJson> Head { get; set; }
        }
        #endregion
        #region 返回体-Test
        public class RetData_TestList
        {
            public List<RetHead_TestJson> Head { get; set; }
            public List<RetBody_TestJson> Body1 { get; set; }
            public List<RetBody_Test2Json> Body2 { get; set; }
        }
        #endregion
        #region 4S店
        #region 返回体-1001
        public class RetData_1001List
        {
            public List<RetBodyHeadJson> Head { get; set; }
            public List<RetBody_CartypeJson> CarBody { get; set; }
            public List<RetBody_WljzJson> WljzBody { get; set; }
            public List<RetBody_LsjzJson> LsjzBody { get; set; }
            public List<RetBody_ZhjzJson> ZhjzBody { get; set; }
        }
        #endregion
        #region 返回体-1002
        public class RetData_1002List
        {
            public List<RetBodyHeadJson> Head { get; set; }
            public List<RetBody_WljzJson> WljzBody { get; set; }
            public List<RetBody_LsjzJson> LsjzBody { get; set; }
            public List<RetBody_ZhjzJson> ZhjzBody { get; set; }
        }
        #endregion
        #region 返回体-1003
        public class RetData_1003List
        {
            public List<RetBodyHeadJson> Head { get; set; }
            public List<RetBody_DetailJson> DetailBody { get; set; }
        }
        #endregion
        #endregion
        #region 章无忧
        #region 返回体-2001
        public class RetData_2001List
        {
            public List<RetBodyHeadJson> Head { get; set; }
        }
        #endregion
        #region 返回体-2003
        public class RetData_2003List
        {
            public List<RetBodyHeadJson> Head { get; set; }
        }
        #endregion
        #region 返回体-2004
        public class RetData_2004List
        {
            public List<RetBodyHeadJson> Head { get; set; }
        }
        #endregion
        #region 返回体-3001
        public class RetData_3001List
        {
            public List<tb_hydee_user> UserHead { get; set; }
            public List<tb_hydee_company> CompanyHead { get; set; }
        }
        #endregion
        #region 返回体-3002
        public class RetData_3002List
        {
            public List<tb_hydee_user> UserHead { get; set; }
            public List<tb_hydee_company> CompanyHead { get; set; }
        }
        #endregion
        #region 返回体-3005
        public class RetData_3005List
        {
            public List<RetBodyHeadJson> Head { get; set; }
        }
        #endregion
        #region 返回体-3001
        public class RetData_3006List
        {
            public List<RetBodyHeadJson> Head { get; set; }
        }
        #endregion
        #region 返回体-付款码收款
        public class RetData_GJ2001List
        {
            public List<interface_gjzh_fkmsk> biz_content { get; set; }
        }
        #endregion
        #endregion
    }
}