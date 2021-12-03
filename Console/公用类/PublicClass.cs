using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Data;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Net;
using System.Web.Script.Serialization;
using System.Runtime.Serialization.Json;
using Newtonsoft.Json;
namespace ConsoleHydee
{
    public static class PublicClass
    {
        #region 格式化
        #region pb自动格式化
        public class telcheckJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_telcheck node = new tb_hydee_telcheck();
                object value = null;
                if (dictionary.TryGetValue("checkguid", out value))
                    node.checkguid = (string)value;
                if (dictionary.TryGetValue("tels", out value))
                    node.tels = (string)value;
                if (dictionary.TryGetValue("checkcode", out value))
                    node.checkcode = (string)value;
                if (dictionary.TryGetValue("outdate", out value))
                    node.outdate = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_telcheck;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.checkguid))
                    dic.Add("checkguid", node.checkguid);
                if (!string.IsNullOrEmpty(node.tels))
                    dic.Add("tels", node.tels);
                if (!string.IsNullOrEmpty(node.checkcode))
                    dic.Add("checkcode", node.checkcode);
                if (!string.IsNullOrEmpty(node.outdate))
                    dic.Add("outdate", node.outdate);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_telcheck) };
                }
            }
        }
        public class addJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_add node = new tb_hydee_add();
                object value = null;
                if (dictionary.TryGetValue("addguid", out value))
                    node.addguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("objectguid", out value))
                    node.objectguid = (string)value;
                if (dictionary.TryGetValue("addtype", out value))
                    node.addtype = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_add;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.addguid))
                    dic.Add("addguid", node.addguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.objectguid))
                    dic.Add("objectguid", node.objectguid);
                if (!string.IsNullOrEmpty(node.addtype))
                    dic.Add("addtype", node.addtype);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_add) };
                }
            }
        }
        public class baseinfoJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_baseinfo node = new tb_hydee_baseinfo();
                object value = null;
                if (dictionary.TryGetValue("platguid", out value))
                    node.platguid = (string)value;
                if (dictionary.TryGetValue("platname", out value))
                    node.platname = (string)value;
                if (dictionary.TryGetValue("platadd", out value))
                    node.platadd = (string)value;
                if (dictionary.TryGetValue("platpeoper", out value))
                    node.platpeoper = (string)value;
                if (dictionary.TryGetValue("plattel", out value))
                    node.plattel = (string)value;
                if (dictionary.TryGetValue("platicons", out value))
                    node.platicons = (string)value;
                if (dictionary.TryGetValue("webservices", out value))
                    node.webservices = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_baseinfo;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.platguid))
                    dic.Add("platguid", node.platguid);
                if (!string.IsNullOrEmpty(node.platname))
                    dic.Add("platname", node.platname);
                if (!string.IsNullOrEmpty(node.platadd))
                    dic.Add("platadd", node.platadd);
                if (!string.IsNullOrEmpty(node.platpeoper))
                    dic.Add("platpeoper", node.platpeoper);
                if (!string.IsNullOrEmpty(node.plattel))
                    dic.Add("plattel", node.plattel);
                if (!string.IsNullOrEmpty(node.platicons))
                    dic.Add("platicons", node.platicons);
                if (!string.IsNullOrEmpty(node.webservices))
                    dic.Add("webservices", node.webservices);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_baseinfo) };
                }
            }
        }
        public class cardJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_card node = new tb_hydee_card();
                object value = null;
                if (dictionary.TryGetValue("cardguid", out value))
                    node.cardguid = (string)value;
                if (dictionary.TryGetValue("cardcode", out value))
                    node.cardcode = (string)value;
                if (dictionary.TryGetValue("cardname", out value))
                    node.cardname = (string)value;
                if (dictionary.TryGetValue("groupname", out value))
                    node.groupname = (string)value;
                if (dictionary.TryGetValue("natures", out value))
                    node.natures = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_card;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.cardguid))
                    dic.Add("cardguid", node.cardguid);
                if (!string.IsNullOrEmpty(node.cardcode))
                    dic.Add("cardcode", node.cardcode);
                if (!string.IsNullOrEmpty(node.cardname))
                    dic.Add("cardname", node.cardname);
                if (!string.IsNullOrEmpty(node.groupname))
                    dic.Add("groupname", node.groupname);
                if (!string.IsNullOrEmpty(node.natures))
                    dic.Add("natures", node.natures);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_card) };
                }
            }
        }
        public class charptertypeJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_charptertype node = new tb_hydee_charptertype();
                object value = null;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("typecode", out value))
                    node.typecode = (string)value;
                if (dictionary.TryGetValue("typename", out value))
                    node.typename = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_charptertype;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.typecode))
                    dic.Add("typecode", node.typecode);
                if (!string.IsNullOrEmpty(node.typename))
                    dic.Add("typename", node.typename);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_charptertype) };
                }
            }
        }
        public class companyautJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companyaut node = new tb_hydee_companyaut();
                object value = null;
                if (dictionary.TryGetValue("recordguid", out value))
                    node.recordguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("applydate", out value))
                    node.applydate = (string)value;
                if (dictionary.TryGetValue("applytype", out value))
                    node.applytype = (string)value;
                if (dictionary.TryGetValue("checkpeoper", out value))
                    node.checkpeoper = (string)value;
                if (dictionary.TryGetValue("checkdate", out value))
                    node.checkdate = (string)value;
                if (dictionary.TryGetValue("checkstatus", out value))
                    node.checkstatus = (string)value;
                if (dictionary.TryGetValue("checksug", out value))
                    node.checksug = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companyaut;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.recordguid))
                    dic.Add("recordguid", node.recordguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.applydate))
                    dic.Add("applydate", node.applydate);
                if (!string.IsNullOrEmpty(node.applytype))
                    dic.Add("applytype", node.applytype);
                if (!string.IsNullOrEmpty(node.checkpeoper))
                    dic.Add("checkpeoper", node.checkpeoper);
                if (!string.IsNullOrEmpty(node.checkdate))
                    dic.Add("checkdate", node.checkdate);
                if (!string.IsNullOrEmpty(node.checkstatus))
                    dic.Add("checkstatus", node.checkstatus);
                if (!string.IsNullOrEmpty(node.checksug))
                    dic.Add("checksug", node.checksug);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companyaut) };
                }
            }
        }
        public class companyJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_company node = new tb_hydee_company();
                object value = null;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("companycode", out value))
                    node.companycode = (string)value;
                if (dictionary.TryGetValue("companyname", out value))
                    node.companyname = (string)value;
                if (dictionary.TryGetValue("companyadd", out value))
                    node.companyadd = (string)value;
                if (dictionary.TryGetValue("companyowner", out value))
                    node.companyowner = (string)value;
                if (dictionary.TryGetValue("tels", out value))
                    node.tels = (string)value;
                if (dictionary.TryGetValue("persons", out value))
                    node.persons = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                if (dictionary.TryGetValue("orderno", out value))
                    node.orderno = (int)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_company;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.companycode))
                    dic.Add("companycode", node.companycode);
                if (!string.IsNullOrEmpty(node.companyname))
                    dic.Add("companyname", node.companyname);
                if (!string.IsNullOrEmpty(node.companyadd))
                    dic.Add("companyadd", node.companyadd);
                if (!string.IsNullOrEmpty(node.companyowner))
                    dic.Add("companyowner", node.companyowner);
                if (!string.IsNullOrEmpty(node.tels))
                    dic.Add("tels", node.tels);
                if (!string.IsNullOrEmpty(node.persons))
                    dic.Add("persons", node.persons);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                if (node.orderno != null)
                    dic.Add("orderno", node.orderno);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_company) };
                }
            }
        }
        public class companycardJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companycard node = new tb_hydee_companycard();
                object value = null;
                if (dictionary.TryGetValue("companycardguid", out value))
                    node.companycardguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("cardguid", out value))
                    node.cardguid = (string)value;
                if (dictionary.TryGetValue("cardpath", out value))
                    node.cardpath = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companycard;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.companycardguid))
                    dic.Add("companycardguid", node.companycardguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.cardguid))
                    dic.Add("cardguid", node.cardguid);
                if (!string.IsNullOrEmpty(node.cardpath))
                    dic.Add("cardpath", node.cardpath);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companycard) };
                }
            }
        }
        public class companychapterJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companychapter node = new tb_hydee_companychapter();
                object value = null;
                if (dictionary.TryGetValue("chapterguid", out value))
                    node.chapterguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("chapterpath", out value))
                    node.chapterpath = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companychapter;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.chapterguid))
                    dic.Add("chapterguid", node.chapterguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.chapterpath))
                    dic.Add("chapterpath", node.chapterpath);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companychapter) };
                }
            }
        }
        public class companycoinJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companycoin node = new tb_hydee_companycoin();
                object value = null;
                if (dictionary.TryGetValue("companycoinguid", out value))
                    node.companycoinguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("coinnum", out value))
                    node.coinnum = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companycoin;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.companycoinguid))
                    dic.Add("companycoinguid", node.companycoinguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (node.coinnum != null)
                    dic.Add("coinnum", node.coinnum);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companycoin) };
                }
            }
        }
        public class companycoininJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companycoinin node = new tb_hydee_companycoinin();
                object value = null;
                if (dictionary.TryGetValue("inguid", out value))
                    node.inguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("ruleguid", out value))
                    node.ruleguid = (string)value;
                if (dictionary.TryGetValue("inmoney", out value))
                    node.inmoney = (decimal)value;
                if (dictionary.TryGetValue("intype", out value))
                    node.intype = (string)value;
                if (dictionary.TryGetValue("addnum", out value))
                    node.addnum = (decimal)value;
                if (dictionary.TryGetValue("havenum", out value))
                    node.havenum = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companycoinin;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.inguid))
                    dic.Add("inguid", node.inguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.ruleguid))
                    dic.Add("ruleguid", node.ruleguid);
                if (node.inmoney != null)
                    dic.Add("inmoney", node.inmoney);
                if (!string.IsNullOrEmpty(node.intype))
                    dic.Add("intype", node.intype);
                if (node.addnum != null)
                    dic.Add("addnum", node.addnum);
                if (node.havenum != null)
                    dic.Add("havenum", node.havenum);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companycoinin) };
                }
            }
        }
        public class companycoinoutJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companycoinout node = new tb_hydee_companycoinout();
                object value = null;
                if (dictionary.TryGetValue("outguid", out value))
                    node.outguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("roleguid", out value))
                    node.roleguid = (string)value;
                if (dictionary.TryGetValue("outtype", out value))
                    node.outtype = (string)value;
                if (dictionary.TryGetValue("delnum", out value))
                    node.delnum = (decimal)value;
                if (dictionary.TryGetValue("havenum", out value))
                    node.havenum = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companycoinout;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.outguid))
                    dic.Add("outguid", node.outguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.roleguid))
                    dic.Add("roleguid", node.roleguid);
                if (!string.IsNullOrEmpty(node.outtype))
                    dic.Add("outtype", node.outtype);
                if (node.delnum != null)
                    dic.Add("delnum", node.delnum);
                if (node.havenum != null)
                    dic.Add("havenum", node.havenum);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companycoinout) };
                }
            }
        }
        public class companyctrmodeJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companyctrmode node = new tb_hydee_companyctrmode();
                object value = null;
                if (dictionary.TryGetValue("modeguid", out value))
                    node.modeguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("modename", out value))
                    node.modename = (string)value;
                if (dictionary.TryGetValue("modepath", out value))
                    node.modepath = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companyctrmode;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.modeguid))
                    dic.Add("modeguid", node.modeguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.modename))
                    dic.Add("modename", node.modename);
                if (!string.IsNullOrEmpty(node.modepath))
                    dic.Add("modepath", node.modepath);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companyctrmode) };
                }
            }
        }
        public class companyctrtypeJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companyctrtype node = new tb_hydee_companyctrtype();
                object value = null;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("typecode", out value))
                    node.typecode = (string)value;
                if (dictionary.TryGetValue("typename", out value))
                    node.typename = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companyctrtype;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.typecode))
                    dic.Add("typecode", node.typecode);
                if (!string.IsNullOrEmpty(node.typename))
                    dic.Add("typename", node.typename);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companyctrtype) };
                }
            }
        }
        public class companyinitJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companyinit node = new tb_hydee_companyinit();
                object value = null;
                if (dictionary.TryGetValue("initguid", out value))
                    node.initguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companyinit;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.initguid))
                    dic.Add("initguid", node.initguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companyinit) };
                }
            }
        }
        public class companynoteJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companynote node = new tb_hydee_companynote();
                object value = null;
                if (dictionary.TryGetValue("noteguid", out value))
                    node.noteguid = (string)value;
                if (dictionary.TryGetValue("securguid", out value))
                    node.securguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("sendmsg", out value))
                    node.sendmsg = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companynote;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.noteguid))
                    dic.Add("noteguid", node.noteguid);
                if (!string.IsNullOrEmpty(node.securguid))
                    dic.Add("securguid", node.securguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.sendmsg))
                    dic.Add("sendmsg", node.sendmsg);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companynote) };
                }
            }
        }
        public class companysecurJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companysecur node = new tb_hydee_companysecur();
                object value = null;
                if (dictionary.TryGetValue("securguid", out value))
                    node.securguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("contralguid", out value))
                    node.contralguid = (string)value;
                if (dictionary.TryGetValue("workguid", out value))
                    node.workguid = (string)value;
                if (dictionary.TryGetValue("chapterguid", out value))
                    node.chapterguid = (string)value;
                if (dictionary.TryGetValue("natures", out value))
                    node.natures = (string)value;
                if (dictionary.TryGetValue("opertype", out value))
                    node.opertype = (string)value;
                if (dictionary.TryGetValue("orderno", out value))
                    node.orderno = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companysecur;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.securguid))
                    dic.Add("securguid", node.securguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.contralguid))
                    dic.Add("contralguid", node.contralguid);
                if (!string.IsNullOrEmpty(node.workguid))
                    dic.Add("workguid", node.workguid);
                if (!string.IsNullOrEmpty(node.chapterguid))
                    dic.Add("chapterguid", node.chapterguid);
                if (!string.IsNullOrEmpty(node.natures))
                    dic.Add("natures", node.natures);
                if (!string.IsNullOrEmpty(node.opertype))
                    dic.Add("opertype", node.opertype);
                if (node.orderno != null)
                    dic.Add("orderno", node.orderno);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companysecur) };
                }
            }
        }
        public class companysecurdetailJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companysecurdetail node = new tb_hydee_companysecurdetail();
                object value = null;
                if (dictionary.TryGetValue("detailguid", out value))
                    node.detailguid = (string)value;
                if (dictionary.TryGetValue("securguid", out value))
                    node.securguid = (string)value;
                if (dictionary.TryGetValue("companycardguid", out value))
                    node.companycardguid = (string)value;
                if (dictionary.TryGetValue("orderno", out value))
                    node.orderno = (decimal)value;
                if (dictionary.TryGetValue("sn", out value))
                    node.sn = (string)value;
                if (dictionary.TryGetValue("paths", out value))
                    node.paths = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companysecurdetail;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.detailguid))
                    dic.Add("detailguid", node.detailguid);
                if (!string.IsNullOrEmpty(node.securguid))
                    dic.Add("securguid", node.securguid);
                if (!string.IsNullOrEmpty(node.companycardguid))
                    dic.Add("companycardguid", node.companycardguid);
                if (node.orderno != null)
                    dic.Add("orderno", node.orderno);
                if (!string.IsNullOrEmpty(node.sn))
                    dic.Add("sn", node.sn);
                if (!string.IsNullOrEmpty(node.paths))
                    dic.Add("paths", node.paths);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companysecurdetail) };
                }
            }
        }
        public class companyworkJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_companywork node = new tb_hydee_companywork();
                object value = null;
                if (dictionary.TryGetValue("companyworkguid", out value))
                    node.companyworkguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("workguid", out value))
                    node.workguid = (string)value;
                if (dictionary.TryGetValue("paths", out value))
                    node.paths = (string)value;
                if (dictionary.TryGetValue("sn", out value))
                    node.sn = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_companywork;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.companyworkguid))
                    dic.Add("companyworkguid", node.companyworkguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.workguid))
                    dic.Add("workguid", node.workguid);
                if (!string.IsNullOrEmpty(node.paths))
                    dic.Add("paths", node.paths);
                if (!string.IsNullOrEmpty(node.sn))
                    dic.Add("sn", node.sn);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_companywork) };
                }
            }
        }
        public class consruleJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_consrule node = new tb_hydee_consrule();
                object value = null;
                if (dictionary.TryGetValue("ruelguid", out value))
                    node.ruelguid = (string)value;
                if (dictionary.TryGetValue("constype", out value))
                    node.constype = (string)value;
                if (dictionary.TryGetValue("conscoin", out value))
                    node.conscoin = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_consrule;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.ruelguid))
                    dic.Add("ruelguid", node.ruelguid);
                if (!string.IsNullOrEmpty(node.constype))
                    dic.Add("constype", node.constype);
                if (node.conscoin != null)
                    dic.Add("conscoin", node.conscoin);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_consrule) };
                }
            }
        }
        public class contralJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_contral node = new tb_hydee_contral();
                object value = null;
                if (dictionary.TryGetValue("contralguid", out value))
                    node.contralguid = (string)value;
                if (dictionary.TryGetValue("ctrcode", out value))
                    node.ctrcode = (string)value;
                if (dictionary.TryGetValue("ctrname", out value))
                    node.ctrname = (string)value;
                if (dictionary.TryGetValue("sn", out value))
                    node.sn = (string)value;
                if (dictionary.TryGetValue("paths", out value))
                    node.paths = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_contral;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.contralguid))
                    dic.Add("contralguid", node.contralguid);
                if (!string.IsNullOrEmpty(node.ctrcode))
                    dic.Add("ctrcode", node.ctrcode);
                if (!string.IsNullOrEmpty(node.ctrname))
                    dic.Add("ctrname", node.ctrname);
                if (!string.IsNullOrEmpty(node.sn))
                    dic.Add("sn", node.sn);
                if (!string.IsNullOrEmpty(node.paths))
                    dic.Add("paths", node.paths);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_contral) };
                }
            }
        }
        public class contraldetailJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_contraldetail node = new tb_hydee_contraldetail();
                object value = null;
                if (dictionary.TryGetValue("detailguid", out value))
                    node.detailguid = (string)value;
                if (dictionary.TryGetValue("contralguid", out value))
                    node.contralguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("sn", out value))
                    node.sn = (string)value;
                if (dictionary.TryGetValue("nature", out value))
                    node.nature = (string)value;
                if (dictionary.TryGetValue("companynatures", out value))
                    node.companynatures = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_contraldetail;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.detailguid))
                    dic.Add("detailguid", node.detailguid);
                if (!string.IsNullOrEmpty(node.contralguid))
                    dic.Add("contralguid", node.contralguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.sn))
                    dic.Add("sn", node.sn);
                if (!string.IsNullOrEmpty(node.nature))
                    dic.Add("nature", node.nature);
                if (!string.IsNullOrEmpty(node.companynatures))
                    dic.Add("companynatures", node.companynatures);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_contraldetail) };
                }
            }
        }
        public class contralpowerJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_contralpower node = new tb_hydee_contralpower();
                object value = null;
                if (dictionary.TryGetValue("powerguid", out value))
                    node.powerguid = (string)value;
                if (dictionary.TryGetValue("contralguid", out value))
                    node.contralguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("powerdate", out value))
                    node.powerdate = (string)value;
                if (dictionary.TryGetValue("powersn", out value))
                    node.powersn = (string)value;
                if (dictionary.TryGetValue("powernum", out value))
                    node.powernum = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_contralpower;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.powerguid))
                    dic.Add("powerguid", node.powerguid);
                if (!string.IsNullOrEmpty(node.contralguid))
                    dic.Add("contralguid", node.contralguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.powerdate))
                    dic.Add("powerdate", node.powerdate);
                if (!string.IsNullOrEmpty(node.powersn))
                    dic.Add("powersn", node.powersn);
                if (node.powernum != null)
                    dic.Add("powernum", node.powernum);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_contralpower) };
                }
            }
        }
        public class naturechangesetJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_naturechangeset node = new tb_hydee_naturechangeset();
                object value = null;
                if (dictionary.TryGetValue("setguid", out value))
                    node.setguid = (string)value;
                if (dictionary.TryGetValue("detailguid", out value))
                    node.detailguid = (string)value;
                if (dictionary.TryGetValue("contralguid", out value))
                    node.contralguid = (string)value;
                if (dictionary.TryGetValue("types", out value))
                    node.types = (string)value;
                if (dictionary.TryGetValue("changeday", out value))
                    node.changeday = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_naturechangeset;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.setguid))
                    dic.Add("setguid", node.setguid);
                if (!string.IsNullOrEmpty(node.detailguid))
                    dic.Add("detailguid", node.detailguid);
                if (!string.IsNullOrEmpty(node.contralguid))
                    dic.Add("contralguid", node.contralguid);
                if (!string.IsNullOrEmpty(node.types))
                    dic.Add("types", node.types);
                if (!string.IsNullOrEmpty(node.changeday))
                    dic.Add("changeday", node.changeday);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_naturechangeset) };
                }
            }
        }
        public class noteJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_note node = new tb_hydee_note();
                object value = null;
                if (dictionary.TryGetValue("noteguid", out value))
                    node.noteguid = (string)value;
                if (dictionary.TryGetValue("securguid", out value))
                    node.securguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("sendmsg", out value))
                    node.sendmsg = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_note;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.noteguid))
                    dic.Add("noteguid", node.noteguid);
                if (!string.IsNullOrEmpty(node.securguid))
                    dic.Add("securguid", node.securguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.sendmsg))
                    dic.Add("sendmsg", node.sendmsg);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_note) };
                }
            }
        }
        public class operchapterJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_operchapter node = new tb_hydee_operchapter();
                object value = null;
                if (dictionary.TryGetValue("applyguid", out value))
                    node.applyguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("contralguid", out value))
                    node.contralguid = (string)value;
                if (dictionary.TryGetValue("applyuserguid", out value))
                    node.applyuserguid = (string)value;
                if (dictionary.TryGetValue("checkuserguid", out value))
                    node.checkuserguid = (string)value;
                if (dictionary.TryGetValue("applydate", out value))
                    node.applydate = (string)value;
                if (dictionary.TryGetValue("checkdate", out value))
                    node.checkdate = (string)value;
                if (dictionary.TryGetValue("checkmsg", out value))
                    node.checkmsg = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_operchapter;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.applyguid))
                    dic.Add("applyguid", node.applyguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.contralguid))
                    dic.Add("contralguid", node.contralguid);
                if (!string.IsNullOrEmpty(node.applyuserguid))
                    dic.Add("applyuserguid", node.applyuserguid);
                if (!string.IsNullOrEmpty(node.checkuserguid))
                    dic.Add("checkuserguid", node.checkuserguid);
                if (!string.IsNullOrEmpty(node.applydate))
                    dic.Add("applydate", node.applydate);
                if (!string.IsNullOrEmpty(node.checkdate))
                    dic.Add("checkdate", node.checkdate);
                if (!string.IsNullOrEmpty(node.checkmsg))
                    dic.Add("checkmsg", node.checkmsg);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_operchapter) };
                }
            }
        }
        public class paramJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_param node = new tb_hydee_param();
                object value = null;
                if (dictionary.TryGetValue("paramguid", out value))
                    node.paramguid = (string)value;
                if (dictionary.TryGetValue("paramcode", out value))
                    node.paramcode = (string)value;
                if (dictionary.TryGetValue("paramname", out value))
                    node.paramname = (string)value;
                if (dictionary.TryGetValue("paramvalues", out value))
                    node.paramvalues = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_param;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.paramguid))
                    dic.Add("paramguid", node.paramguid);
                if (!string.IsNullOrEmpty(node.paramcode))
                    dic.Add("paramcode", node.paramcode);
                if (!string.IsNullOrEmpty(node.paramname))
                    dic.Add("paramname", node.paramname);
                if (!string.IsNullOrEmpty(node.paramvalues))
                    dic.Add("paramvalues", node.paramvalues);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_param) };
                }
            }
        }
        public class powerJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_power node = new tb_hydee_power();
                object value = null;
                if (dictionary.TryGetValue("powerguid", out value))
                    node.powerguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("chapterguid", out value))
                    node.chapterguid = (string)value;
                if (dictionary.TryGetValue("parentid", out value))
                    node.parentid = (decimal)value;
                if (dictionary.TryGetValue("natures", out value))
                    node.natures = (string)value;
                if (dictionary.TryGetValue("parent_ids", out value))
                    node.parent_ids = (string)value;
                if (dictionary.TryGetValue("powername", out value))
                    node.powername = (string)value;
                if (dictionary.TryGetValue("sortno", out value))
                    node.sortno = (decimal)value;
                if (dictionary.TryGetValue("href", out value))
                    node.href = (string)value;
                if (dictionary.TryGetValue("target", out value))
                    node.target = (string)value;
                if (dictionary.TryGetValue("icon", out value))
                    node.icon = (string)value;
                if (dictionary.TryGetValue("ifview", out value))
                    node.ifview = (string)value;
                if (dictionary.TryGetValue("height", out value))
                    node.height = (decimal)value;
                if (dictionary.TryGetValue("authorities", out value))
                    node.authorities = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_power;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.powerguid))
                    dic.Add("powerguid", node.powerguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.chapterguid))
                    dic.Add("chapterguid", node.chapterguid);
                if (node.parentid != null)
                    dic.Add("parentid", node.parentid);
                if (!string.IsNullOrEmpty(node.natures))
                    dic.Add("natures", node.natures);
                if (!string.IsNullOrEmpty(node.parent_ids))
                    dic.Add("parent_ids", node.parent_ids);
                if (!string.IsNullOrEmpty(node.powername))
                    dic.Add("powername", node.powername);
                if (node.sortno != null)
                    dic.Add("sortno", node.sortno);
                if (!string.IsNullOrEmpty(node.href))
                    dic.Add("href", node.href);
                if (!string.IsNullOrEmpty(node.target))
                    dic.Add("target", node.target);
                if (!string.IsNullOrEmpty(node.icon))
                    dic.Add("icon", node.icon);
                if (!string.IsNullOrEmpty(node.ifview))
                    dic.Add("ifview", node.ifview);
                if (node.height != null)
                    dic.Add("height", node.height);
                if (!string.IsNullOrEmpty(node.authorities))
                    dic.Add("authorities", node.authorities);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_power) };
                }
            }
        }
        public class rechargeruleJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_rechargerule node = new tb_hydee_rechargerule();
                object value = null;
                if (dictionary.TryGetValue("ruleguid", out value))
                    node.ruleguid = (string)value;
                if (dictionary.TryGetValue("rechargetype", out value))
                    node.rechargetype = (string)value;
                if (dictionary.TryGetValue("rechargecoin", out value))
                    node.rechargecoin = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_rechargerule;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.ruleguid))
                    dic.Add("ruleguid", node.ruleguid);
                if (!string.IsNullOrEmpty(node.rechargetype))
                    dic.Add("rechargetype", node.rechargetype);
                if (node.rechargecoin != null)
                    dic.Add("rechargecoin", node.rechargecoin);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_rechargerule) };
                }
            }
        }
        public class snJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_sn node = new tb_hydee_sn();
                object value = null;
                if (dictionary.TryGetValue("snguid", out value))
                    node.snguid = (string)value;
                if (dictionary.TryGetValue("sn", out value))
                    node.sn = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_sn;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.snguid))
                    dic.Add("snguid", node.snguid);
                if (!string.IsNullOrEmpty(node.sn))
                    dic.Add("sn", node.sn);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_sn) };
                }
            }
        }
        public class userJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_user node = new tb_hydee_user();
                object value = null;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("usercode", out value))
                    node.usercode = (string)value;
                if (dictionary.TryGetValue("username", out value))
                    node.username = (string)value;
                if (dictionary.TryGetValue("loginname", out value))
                    node.loginname = (string)value;
                if (dictionary.TryGetValue("usersex", out value))
                    node.usersex = (string)value;
                if (dictionary.TryGetValue("userpass", out value))
                    node.userpass = (string)value;
                if (dictionary.TryGetValue("ages", out value))
                    node.ages = (decimal)value;
                if (dictionary.TryGetValue("cardno", out value))
                    node.cardno = (string)value;
                if (dictionary.TryGetValue("births", out value))
                    node.births = (string)value;
                if (dictionary.TryGetValue("tels", out value))
                    node.tels = (string)value;
                if (dictionary.TryGetValue("email", out value))
                    node.email = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                if (dictionary.TryGetValue("orderno", out value))
                    node.orderno = (int)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_user;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.usercode))
                    dic.Add("usercode", node.usercode);
                if (!string.IsNullOrEmpty(node.username))
                    dic.Add("username", node.username);
                if (!string.IsNullOrEmpty(node.loginname))
                    dic.Add("loginname", node.loginname);
                if (!string.IsNullOrEmpty(node.usersex))
                    dic.Add("usersex", node.usersex);
                if (!string.IsNullOrEmpty(node.userpass))
                    dic.Add("userpass", node.userpass);
                if (node.ages != null)
                    dic.Add("ages", node.ages);
                if (!string.IsNullOrEmpty(node.cardno))
                    dic.Add("cardno", node.cardno);
                if (!string.IsNullOrEmpty(node.births))
                    dic.Add("births", node.births);
                if (!string.IsNullOrEmpty(node.tels))
                    dic.Add("tels", node.tels);
                if (!string.IsNullOrEmpty(node.email))
                    dic.Add("email", node.email);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                if (node.orderno != null)
                    dic.Add("orderno", node.orderno);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_user) };
                }
            }
        }
        public class userautJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_useraut node = new tb_hydee_useraut();
                object value = null;
                if (dictionary.TryGetValue("recordguid", out value))
                    node.recordguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("applydate", out value))
                    node.applydate = (string)value;
                if (dictionary.TryGetValue("applytype", out value))
                    node.applytype = (string)value;
                if (dictionary.TryGetValue("checkpeoper", out value))
                    node.checkpeoper = (string)value;
                if (dictionary.TryGetValue("checkdate", out value))
                    node.checkdate = (string)value;
                if (dictionary.TryGetValue("checkstatus", out value))
                    node.checkstatus = (string)value;
                if (dictionary.TryGetValue("checksug", out value))
                    node.checksug = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_useraut;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.recordguid))
                    dic.Add("recordguid", node.recordguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.applydate))
                    dic.Add("applydate", node.applydate);
                if (!string.IsNullOrEmpty(node.applytype))
                    dic.Add("applytype", node.applytype);
                if (!string.IsNullOrEmpty(node.checkpeoper))
                    dic.Add("checkpeoper", node.checkpeoper);
                if (!string.IsNullOrEmpty(node.checkdate))
                    dic.Add("checkdate", node.checkdate);
                if (!string.IsNullOrEmpty(node.checkstatus))
                    dic.Add("checkstatus", node.checkstatus);
                if (!string.IsNullOrEmpty(node.checksug))
                    dic.Add("checksug", node.checksug);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_useraut) };
                }
            }
        }
        public class usercardJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usercard node = new tb_hydee_usercard();
                object value = null;
                if (dictionary.TryGetValue("usercardguid", out value))
                    node.usercardguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("cardguid", out value))
                    node.cardguid = (string)value;
                if (dictionary.TryGetValue("cardpath", out value))
                    node.cardpath = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                if (dictionary.TryGetValue("cardbyte", out value))
                    node.cardbyte = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usercard;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.usercardguid))
                    dic.Add("usercardguid", node.usercardguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.cardguid))
                    dic.Add("cardguid", node.cardguid);
                if (!string.IsNullOrEmpty(node.cardpath))
                    dic.Add("cardpath", node.cardpath);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                if (!string.IsNullOrEmpty(node.cardbyte))
                    dic.Add("cardbyte", node.cardbyte);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usercard) };
                }
            }
        }
        public class userchapterJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_userchapter node = new tb_hydee_userchapter();
                object value = null;
                if (dictionary.TryGetValue("chapterguid", out value))
                    node.chapterguid = (string)value;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("chapterpath", out value))
                    node.chapterpath = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_userchapter;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.chapterguid))
                    dic.Add("chapterguid", node.chapterguid);
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.chapterpath))
                    dic.Add("chapterpath", node.chapterpath);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_userchapter) };
                }
            }
        }
        public class usercoinJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usercoin node = new tb_hydee_usercoin();
                object value = null;
                if (dictionary.TryGetValue("usercoinguid", out value))
                    node.usercoinguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("coinnum", out value))
                    node.coinnum = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usercoin;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.usercoinguid))
                    dic.Add("usercoinguid", node.usercoinguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (node.coinnum != null)
                    dic.Add("coinnum", node.coinnum);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usercoin) };
                }
            }
        }
        public class usercoininJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usercoinin node = new tb_hydee_usercoinin();
                object value = null;
                if (dictionary.TryGetValue("inguid", out value))
                    node.inguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("ruleguid", out value))
                    node.ruleguid = (string)value;
                if (dictionary.TryGetValue("inmoney", out value))
                    node.inmoney = (decimal)value;
                if (dictionary.TryGetValue("intype", out value))
                    node.intype = (string)value;
                if (dictionary.TryGetValue("addnum", out value))
                    node.addnum = (decimal)value;
                if (dictionary.TryGetValue("havenum", out value))
                    node.havenum = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usercoinin;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.inguid))
                    dic.Add("inguid", node.inguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.ruleguid))
                    dic.Add("ruleguid", node.ruleguid);
                if (node.inmoney != null)
                    dic.Add("inmoney", node.inmoney);
                if (!string.IsNullOrEmpty(node.intype))
                    dic.Add("intype", node.intype);
                if (node.addnum != null)
                    dic.Add("addnum", node.addnum);
                if (node.havenum != null)
                    dic.Add("havenum", node.havenum);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usercoinin) };
                }
            }
        }
        public class usercoinoutJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usercoinout node = new tb_hydee_usercoinout();
                object value = null;
                if (dictionary.TryGetValue("outguid", out value))
                    node.outguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("roleguid", out value))
                    node.roleguid = (string)value;
                if (dictionary.TryGetValue("outtype", out value))
                    node.outtype = (string)value;
                if (dictionary.TryGetValue("delnum", out value))
                    node.delnum = (decimal)value;
                if (dictionary.TryGetValue("havenum", out value))
                    node.havenum = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usercoinout;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.outguid))
                    dic.Add("outguid", node.outguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.roleguid))
                    dic.Add("roleguid", node.roleguid);
                if (!string.IsNullOrEmpty(node.outtype))
                    dic.Add("outtype", node.outtype);
                if (node.delnum != null)
                    dic.Add("delnum", node.delnum);
                if (node.havenum != null)
                    dic.Add("havenum", node.havenum);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usercoinout) };
                }
            }
        }
        public class usercompanyJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usercompany node = new tb_hydee_usercompany();
                object value = null;
                if (dictionary.TryGetValue("usercompanyguid", out value))
                    node.usercompanyguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("natures", out value))
                    node.natures = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usercompany;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.usercompanyguid))
                    dic.Add("usercompanyguid", node.usercompanyguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.natures))
                    dic.Add("natures", node.natures);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usercompany) };
                }
            }
        }
        public class userctrmodeJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_userctrmode node = new tb_hydee_userctrmode();
                object value = null;
                if (dictionary.TryGetValue("modeguid", out value))
                    node.modeguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("modename", out value))
                    node.modename = (string)value;
                if (dictionary.TryGetValue("modepath", out value))
                    node.modepath = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_userctrmode;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.modeguid))
                    dic.Add("modeguid", node.modeguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.modename))
                    dic.Add("modename", node.modename);
                if (!string.IsNullOrEmpty(node.modepath))
                    dic.Add("modepath", node.modepath);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_userctrmode) };
                }
            }
        }
        public class userctrtypeJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_userctrtype node = new tb_hydee_userctrtype();
                object value = null;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("typecode", out value))
                    node.typecode = (string)value;
                if (dictionary.TryGetValue("typename", out value))
                    node.typename = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_userctrtype;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.typecode))
                    dic.Add("typecode", node.typecode);
                if (!string.IsNullOrEmpty(node.typename))
                    dic.Add("typename", node.typename);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_userctrtype) };
                }
            }
        }
        public class userfindJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_userfind node = new tb_hydee_userfind();
                object value = null;
                if (dictionary.TryGetValue("findguid", out value))
                    node.findguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("checkuser", out value))
                    node.checkuser = (string)value;
                if (dictionary.TryGetValue("finddate", out value))
                    node.finddate = (string)value;
                if (dictionary.TryGetValue("findtype", out value))
                    node.findtype = (string)value;
                if (dictionary.TryGetValue("findsn", out value))
                    node.findsn = (string)value;
                if (dictionary.TryGetValue("checkdate", out value))
                    node.checkdate = (string)value;
                if (dictionary.TryGetValue("checksug", out value))
                    node.checksug = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_userfind;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.findguid))
                    dic.Add("findguid", node.findguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.checkuser))
                    dic.Add("checkuser", node.checkuser);
                if (!string.IsNullOrEmpty(node.finddate))
                    dic.Add("finddate", node.finddate);
                if (!string.IsNullOrEmpty(node.findtype))
                    dic.Add("findtype", node.findtype);
                if (!string.IsNullOrEmpty(node.findsn))
                    dic.Add("findsn", node.findsn);
                if (!string.IsNullOrEmpty(node.checkdate))
                    dic.Add("checkdate", node.checkdate);
                if (!string.IsNullOrEmpty(node.checksug))
                    dic.Add("checksug", node.checksug);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_userfind) };
                }
            }
        }
        public class userpowerJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_userpower node = new tb_hydee_userpower();
                object value = null;
                if (dictionary.TryGetValue("userpowerguid", out value))
                    node.userpowerguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("powerguid", out value))
                    node.powerguid = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_userpower;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.userpowerguid))
                    dic.Add("userpowerguid", node.userpowerguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.powerguid))
                    dic.Add("powerguid", node.powerguid);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_userpower) };
                }
            }
        }
        public class usersecurJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usersecur node = new tb_hydee_usersecur();
                object value = null;
                if (dictionary.TryGetValue("securguid", out value))
                    node.securguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("contralguid", out value))
                    node.contralguid = (string)value;
                if (dictionary.TryGetValue("workguid", out value))
                    node.workguid = (string)value;
                if (dictionary.TryGetValue("chapterguid", out value))
                    node.chapterguid = (string)value;
                if (dictionary.TryGetValue("natures", out value))
                    node.natures = (string)value;
                if (dictionary.TryGetValue("opertype", out value))
                    node.opertype = (string)value;
                if (dictionary.TryGetValue("orderno", out value))
                    node.orderno = (decimal)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usersecur;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.securguid))
                    dic.Add("securguid", node.securguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.contralguid))
                    dic.Add("contralguid", node.contralguid);
                if (!string.IsNullOrEmpty(node.workguid))
                    dic.Add("workguid", node.workguid);
                if (!string.IsNullOrEmpty(node.chapterguid))
                    dic.Add("chapterguid", node.chapterguid);
                if (!string.IsNullOrEmpty(node.natures))
                    dic.Add("natures", node.natures);
                if (!string.IsNullOrEmpty(node.opertype))
                    dic.Add("opertype", node.opertype);
                if (node.orderno != null)
                    dic.Add("orderno", node.orderno);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usersecur) };
                }
            }
        }
        public class usersecurdetailJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usersecurdetail node = new tb_hydee_usersecurdetail();
                object value = null;
                if (dictionary.TryGetValue("detailguid", out value))
                    node.detailguid = (string)value;
                if (dictionary.TryGetValue("securguid", out value))
                    node.securguid = (string)value;
                if (dictionary.TryGetValue("usercardguid", out value))
                    node.usercardguid = (string)value;
                if (dictionary.TryGetValue("orderno", out value))
                    node.orderno = (decimal)value;
                if (dictionary.TryGetValue("sn", out value))
                    node.sn = (string)value;
                if (dictionary.TryGetValue("paths", out value))
                    node.paths = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usersecurdetail;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.detailguid))
                    dic.Add("detailguid", node.detailguid);
                if (!string.IsNullOrEmpty(node.securguid))
                    dic.Add("securguid", node.securguid);
                if (!string.IsNullOrEmpty(node.usercardguid))
                    dic.Add("usercardguid", node.usercardguid);
                if (node.orderno != null)
                    dic.Add("orderno", node.orderno);
                if (!string.IsNullOrEmpty(node.sn))
                    dic.Add("sn", node.sn);
                if (!string.IsNullOrEmpty(node.paths))
                    dic.Add("paths", node.paths);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usersecurdetail) };
                }
            }
        }
        public class usersignJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usersign node = new tb_hydee_usersign();
                object value = null;
                if (dictionary.TryGetValue("signguid", out value))
                    node.signguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("signname", out value))
                    node.signname = (string)value;
                if (dictionary.TryGetValue("signpath", out value))
                    node.signpath = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usersign;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.signguid))
                    dic.Add("signguid", node.signguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.signname))
                    dic.Add("signname", node.signname);
                if (!string.IsNullOrEmpty(node.signpath))
                    dic.Add("signpath", node.signpath);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usersign) };
                }
            }
        }
        public class usertypeJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_usertype node = new tb_hydee_usertype();
                object value = null;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("typecode", out value))
                    node.typecode = (string)value;
                if (dictionary.TryGetValue("typename", out value))
                    node.typename = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_usertype;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.typecode))
                    dic.Add("typecode", node.typecode);
                if (!string.IsNullOrEmpty(node.typename))
                    dic.Add("typename", node.typename);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_usertype) };
                }
            }
        }
        public class userworkJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_userwork node = new tb_hydee_userwork();
                object value = null;
                if (dictionary.TryGetValue("userworkguid", out value))
                    node.userworkguid = (string)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("workguid", out value))
                    node.workguid = (string)value;
                if (dictionary.TryGetValue("paths", out value))
                    node.paths = (string)value;
                if (dictionary.TryGetValue("sn", out value))
                    node.sn = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_userwork;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.userworkguid))
                    dic.Add("userworkguid", node.userworkguid);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.workguid))
                    dic.Add("workguid", node.workguid);
                if (!string.IsNullOrEmpty(node.paths))
                    dic.Add("paths", node.paths);
                if (!string.IsNullOrEmpty(node.sn))
                    dic.Add("sn", node.sn);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_userwork) };
                }
            }
        }
        public class workdetailJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_workdetail node = new tb_hydee_workdetail();
                object value = null;
                if (dictionary.TryGetValue("detailguid", out value))
                    node.detailguid = (string)value;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("cardguid", out value))
                    node.cardguid = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_workdetail;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.detailguid))
                    dic.Add("detailguid", node.detailguid);
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.cardguid))
                    dic.Add("cardguid", node.cardguid);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_workdetail) };
                }
            }
        }
        public class workreleaseJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_workrelease node = new tb_hydee_workrelease();
                object value = null;
                if (dictionary.TryGetValue("workguid", out value))
                    node.workguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("releasedate", out value))
                    node.releasedate = (string)value;
                if (dictionary.TryGetValue("releaseuser", out value))
                    node.releaseuser = (string)value;
                if (dictionary.TryGetValue("status", out value))
                    node.status = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_workrelease;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.workguid))
                    dic.Add("workguid", node.workguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.releasedate))
                    dic.Add("releasedate", node.releasedate);
                if (!string.IsNullOrEmpty(node.releaseuser))
                    dic.Add("releaseuser", node.releaseuser);
                if (!string.IsNullOrEmpty(node.status))
                    dic.Add("status", node.status);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_workrelease) };
                }
            }
        }
        public class worktypeJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                tb_hydee_worktype node = new tb_hydee_worktype();
                object value = null;
                if (dictionary.TryGetValue("typeguid", out value))
                    node.typeguid = (string)value;
                if (dictionary.TryGetValue("companyguid", out value))
                    node.companyguid = (string)value;
                if (dictionary.TryGetValue("typecode", out value))
                    node.typecode = (string)value;
                if (dictionary.TryGetValue("typename", out value))
                    node.typename = (string)value;
                if (dictionary.TryGetValue("operuser", out value))
                    node.operuser = (string)value;
                if (dictionary.TryGetValue("operdate", out value))
                    node.operdate = (string)value;
                if (dictionary.TryGetValue("remark", out value))
                    node.remark = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as tb_hydee_worktype;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.typeguid))
                    dic.Add("typeguid", node.typeguid);
                if (!string.IsNullOrEmpty(node.companyguid))
                    dic.Add("companyguid", node.companyguid);
                if (!string.IsNullOrEmpty(node.typecode))
                    dic.Add("typecode", node.typecode);
                if (!string.IsNullOrEmpty(node.typename))
                    dic.Add("typename", node.typename);
                if (!string.IsNullOrEmpty(node.operuser))
                    dic.Add("operuser", node.operuser);
                if (!string.IsNullOrEmpty(node.operdate))
                    dic.Add("operdate", node.operdate);
                if (!string.IsNullOrEmpty(node.remark))
                    dic.Add("remark", node.remark);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(tb_hydee_worktype) };
                }
            }
        }
        #endregion

        #region 测试JSON格式化
        public class TestJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                RetBody_TestJson node = new RetBody_TestJson();
                object value = null;
                if (dictionary.TryGetValue("color", out value))
                    node.color = (string)value;
                if (dictionary.TryGetValue("price", out value))
                    node.price = (int)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as RetBody_TestJson;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.color))
                    dic.Add("color", node.color);
                if (node.price != null)
                    dic.Add("price", node.price);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(RetBody_TestJson) };
                }
            }
        }
        public class Test2JSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                RetBody_Test2Json node = new RetBody_Test2Json();
                object value = null;
                if (dictionary.TryGetValue("car", out value))
                    node.car = (string)value;
                if (dictionary.TryGetValue("size", out value))
                    node.size = (int)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as RetBody_Test2Json;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.car))
                    dic.Add("car", node.car);
                if (node.size != null)
                    dic.Add("size", node.size);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(RetBody_Test2Json) };
                }
            }
        }
        #endregion

        #region 返回体头格式化
        public class RetHeadJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                RetBodyHeadJson node = new RetBodyHeadJson();
                object value = null;
                if (dictionary.TryGetValue("carname", out value))
                    node.carname = (string)value;
                if (dictionary.TryGetValue("controltype", out value))
                    node.controltype = (int)value;
                if (dictionary.TryGetValue("ifbody", out value))
                    node.ifbody = (int)value;
                if (dictionary.TryGetValue("userguid", out value))
                    node.userguid = (string)value;
                if (dictionary.TryGetValue("username", out value))
                    node.username = (string)value;
                if (dictionary.TryGetValue("userpower", out value))
                    node.userpower = (string)value;
                if (dictionary.TryGetValue("orgguid", out value))
                    node.orgguid = (string)value;
                if (dictionary.TryGetValue("orgname", out value))
                    node.orgname = (string)value;
                if (dictionary.TryGetValue("cardguid", out value))
                    node.cardguid = (string)value;
                if (dictionary.TryGetValue("cardname", out value))
                    node.cardname = (string)value;
                if (dictionary.TryGetValue("usercode", out value))
                    node.usercode = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as RetBodyHeadJson;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.carname))
                    dic.Add("carname", node.carname);
                if (!string.IsNullOrEmpty(node.userguid))
                    dic.Add("userguid", node.userguid);
                if (!string.IsNullOrEmpty(node.username))
                    dic.Add("username", node.username);
                if (!string.IsNullOrEmpty(node.userpower))
                    dic.Add("userpower", node.userpower);
                if (!string.IsNullOrEmpty(node.orgguid))
                    dic.Add("orgguid", node.orgguid);
                if (!string.IsNullOrEmpty(node.orgname))
                    dic.Add("orgname", node.orgname);
                if (node.controltype != null)
                    dic.Add("controltype", node.controltype);
                if (node.ifbody != null)
                    dic.Add("ifbody", node.ifbody);
                if (!string.IsNullOrEmpty(node.cardguid))
                    dic.Add("cardguid", node.cardguid);
                if (!string.IsNullOrEmpty(node.cardname))
                    dic.Add("cardname", node.cardname);
                if (!string.IsNullOrEmpty(node.usercode))
                    dic.Add("usercode", node.usercode);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(RetBodyHeadJson) };
                }
            }
        }
        #endregion

        #region 请求体头格式化
        public class ReqHeadJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                ReqBodyHeadJson node = new ReqBodyHeadJson();
                object value = null;
                if (dictionary.TryGetValue("carname", out value))
                    node.carname = (string)value;
                if (dictionary.TryGetValue("type", out value))
                    node.type = (int)value;
                if (dictionary.TryGetValue("find1", out value))
                    node.find1 = (string)value;
                if (dictionary.TryGetValue("find2", out value))
                    node.find2 = (string)value;
                if (dictionary.TryGetValue("find3", out value))
                    node.find3 = (string)value;
                if (dictionary.TryGetValue("find4", out value))
                    node.find4 = (string)value;
                if (dictionary.TryGetValue("find5", out value))
                    node.find5 = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as ReqBodyHeadJson;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.carname))
                    dic.Add("carname", node.carname);
                if (node.type != null)
                    dic.Add("type", node.type);
                if (!string.IsNullOrEmpty(node.find1))
                    dic.Add("find1", node.find1);
                if (!string.IsNullOrEmpty(node.find2))
                    dic.Add("find2", node.find2);
                if (!string.IsNullOrEmpty(node.find3))
                    dic.Add("find3", node.find3);
                if (!string.IsNullOrEmpty(node.find4))
                    dic.Add("find4", node.find4);
                if (!string.IsNullOrEmpty(node.find5))
                    dic.Add("find5", node.find5);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(ReqBodyHeadJson) };
                }
            }
        }
        #endregion

        #region 汽车分类格式化
        public class CartypeJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                RetBody_CartypeJson node = new RetBody_CartypeJson();
                object value = null;
                if (dictionary.TryGetValue("carname", out value))
                    node.carname = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as RetBody_CartypeJson;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.carname))
                    dic.Add("carname", node.carname);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(RetBody_CartypeJson) };
                }
            }
        }
        #endregion

        #region 未来价值格式化
        public class WljzJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                RetBody_WljzJson node = new RetBody_WljzJson();
                object value = null;
                if (dictionary.TryGetValue("jdy", out value))
                    node.jdy = (string)value;
                if (dictionary.TryGetValue("kyzl", out value))
                    node.kyzl = (int)value;
                if (dictionary.TryGetValue("ndzl", out value))
                    node.ndzl = (int)value;
                if (dictionary.TryGetValue("ngzl", out value))
                    node.ngzl = (int)value;
                if (dictionary.TryGetValue("qlzl", out value))
                    node.qlzl = (int)value;
                if (dictionary.TryGetValue("zj", out value))
                    node.zj = (int)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as RetBody_WljzJson;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.jdy))
                    dic.Add("jdy", node.jdy);
                if (node.kyzl != null)
                    dic.Add("kyzl", node.kyzl);
                if (node.ndzl != null)
                    dic.Add("ndzl", node.ndzl);
                if (node.ngzl != null)
                    dic.Add("ngzl", node.ngzl);
                if (node.qlzl != null)
                    dic.Add("qlzl", node.qlzl);
                if (node.zj != null)
                    dic.Add("zj", node.zj);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(RetBody_WljzJson) };
                }
            }
        }
        #endregion

        #region 历史价值格式化
        public class LsjzJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                RetBody_LsjzJson node = new RetBody_LsjzJson();
                object value = null;
                if (dictionary.TryGetValue("jdy", out value))
                    node.jdy = (string)value;
                if (dictionary.TryGetValue("xybc", out value))
                    node.xybc = (int)value;
                if (dictionary.TryGetValue("ybfz", out value))
                    node.ybfz = (int)value;
                if (dictionary.TryGetValue("ybjz", out value))
                    node.ybjz = (int)value;
                if (dictionary.TryGetValue("ybwl", out value))
                    node.ybwl = (int)value;
                if (dictionary.TryGetValue("zybc", out value))
                    node.zybc = (int)value;
                if (dictionary.TryGetValue("zyfz", out value))
                    node.zyfz = (int)value;
                if (dictionary.TryGetValue("zyjz", out value))
                    node.zyjz = (int)value;
                if (dictionary.TryGetValue("zywl", out value))
                    node.zywl = (int)value;
                if (dictionary.TryGetValue("zj", out value))
                    node.zj = (int)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as RetBody_LsjzJson;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.jdy))
                    dic.Add("jdy", node.jdy);
                if (node.xybc != null)
                    dic.Add("xybc", node.xybc);
                if (node.ybfz != null)
                    dic.Add("ybfz", node.ybfz);
                if (node.ybjz != null)
                    dic.Add("ybjz", node.ybjz);
                if (node.ybwl != null)
                    dic.Add("ybwl", node.ybwl);
                if (node.zybc != null)
                    dic.Add("zybc", node.zybc);
                if (node.zyfz != null)
                    dic.Add("zyfz", node.zyfz);
                if (node.zyjz != null)
                    dic.Add("zyjz", node.zyjz);
                if (node.zywl != null)
                    dic.Add("zywl", node.zywl);
                if (node.zj != null)
                    dic.Add("zj", node.zj);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(RetBody_LsjzJson) };
                }
            }
        }
        #endregion

        #region 综合价值格式化
        public class ZhjzJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                RetBody_ZhjzJson node = new RetBody_ZhjzJson();
                object value = null;
                if (dictionary.TryGetValue("lsjz", out value))
                    node.lsjz = (string)value;
                if (dictionary.TryGetValue("ngzl", out value))
                    node.ngzl = (int)value;
                if (dictionary.TryGetValue("kyzl", out value))
                    node.kyzl = (int)value;
                if (dictionary.TryGetValue("ndzl", out value))
                    node.ndzl = (int)value;
                if (dictionary.TryGetValue("qlzl", out value))
                    node.qlzl = (int)value;
                if (dictionary.TryGetValue("zj", out value))
                    node.zj = (int)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as RetBody_ZhjzJson;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.lsjz))
                    dic.Add("lsjz", node.lsjz);
                if (node.kyzl != null)
                    dic.Add("kyzl", node.kyzl);
                if (node.ndzl != null)
                    dic.Add("ndzl", node.ndzl);
                if (node.ngzl != null)
                    dic.Add("ngzl", node.ngzl);
                if (node.qlzl != null)
                    dic.Add("qlzl", node.qlzl);
                if (node.zj != null)
                    dic.Add("zj", node.zj);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(RetBody_ZhjzJson) };
                }
            }
        }
        #endregion

        #region 明细数据格式化
        public class DataJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                RetBody_DetailJson node = new RetBody_DetailJson();
                object value = null;
                if (dictionary.TryGetValue("car", out value))
                    node.car = (string)value;
                if (dictionary.TryGetValue("dph", out value))
                    node.dph = (string)value;
                if (dictionary.TryGetValue("hyd", out value))
                    node.hyd = (string)value;
                if (dictionary.TryGetValue("pc", out value))
                    node.pc = (decimal)value;
                if (dictionary.TryGetValue("jsje", out value))
                    node.jsje = (decimal)value;
                if (dictionary.TryGetValue("jsrq", out value))
                    node.jsrq = (string)value;
                if (dictionary.TryGetValue("kdj", out value))
                    node.kdj = (decimal)value;
                if (dictionary.TryGetValue("jgts", out value))
                    node.jgts = (decimal)value;
                if (dictionary.TryGetValue("gcts", out value))
                    node.gcts = (decimal)value;
                if (dictionary.TryGetValue("cl", out value))
                    node.cl = (decimal)value;
                if (dictionary.TryGetValue("zhlc", out value))
                    node.zhlc = (decimal)value;
                if (dictionary.TryGetValue("gmrq", out value))
                    node.gmrq = (string)value;
                if (dictionary.TryGetValue("wxlb", out value))
                    node.wxlb = (string)value;
                if (dictionary.TryGetValue("jdy", out value))
                    node.jdy = (string)value;
                if (dictionary.TryGetValue("scrq", out value))
                    node.scrq = (string)value;
                if (dictionary.TryGetValue("lsjz", out value))
                    node.lsjz = (string)value;
                if (dictionary.TryGetValue("wljz", out value))
                    node.wljz = (string)value;
                if (dictionary.TryGetValue("ldkhqjlb", out value))
                    node.ldkhqjlb = (string)value;
                if (dictionary.TryGetValue("kdjqjlb", out value))
                    node.kdjqjlb = (string)value;
                if (dictionary.TryGetValue("whdqjlb", out value))
                    node.whdqjlb = (string)value;
                if (dictionary.TryGetValue("qlqjlb", out value))
                    node.qlqjlb = (string)value;
                if (dictionary.TryGetValue("gchzlc", out value))
                    node.gchzlc = (decimal)value;
                if (dictionary.TryGetValue("escqjlb", out value))
                    node.escqjlb = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as RetBody_DetailJson;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.car))
                    dic.Add("car", node.car);
                if (!string.IsNullOrEmpty(node.dph))
                    dic.Add("dph", node.dph);
                if (!string.IsNullOrEmpty(node.hyd))
                    dic.Add("hyd", node.hyd);
                if (node.pc != null)
                    dic.Add("pc", node.pc);
                if (node.jsje != null)
                    dic.Add("jsje", node.jsje);
                if (!string.IsNullOrEmpty(node.jsrq))
                    dic.Add("jsrq", node.jsrq);
                if (node.kdj != null)
                    dic.Add("kdj", node.kdj);
                if (node.jgts != null)
                    dic.Add("jgts", node.jgts);
                if (node.gcts != null)
                    dic.Add("gcts", node.gcts);
                if (node.cl != null)
                    dic.Add("cl", node.cl);
                if (node.zhlc != null)
                    dic.Add("zhlc", node.zhlc);
                if (!string.IsNullOrEmpty(node.gmrq))
                    dic.Add("gmrq", node.gmrq);
                if (!string.IsNullOrEmpty(node.wxlb))
                    dic.Add("wxlb", node.wxlb);
                if (!string.IsNullOrEmpty(node.jdy))
                    dic.Add("jdy", node.jdy);
                if (!string.IsNullOrEmpty(node.scrq))
                    dic.Add("scrq", node.scrq);
                if (!string.IsNullOrEmpty(node.lsjz))
                    dic.Add("lsjz", node.lsjz);
                if (!string.IsNullOrEmpty(node.wljz))
                    dic.Add("wljz", node.wljz);
                if (!string.IsNullOrEmpty(node.ldkhqjlb))
                    dic.Add("ldkhqjlb", node.ldkhqjlb);
                if (!string.IsNullOrEmpty(node.kdjqjlb))
                    dic.Add("kdjqjlb", node.kdjqjlb);
                if (!string.IsNullOrEmpty(node.whdqjlb))
                    dic.Add("whdqjlb", node.whdqjlb);
                if (!string.IsNullOrEmpty(node.qlqjlb))
                    dic.Add("qlqjlb", node.qlqjlb);
                if (node.gchzlc != null)
                    dic.Add("gchzlc", node.gchzlc);
                if (!string.IsNullOrEmpty(node.escqjlb))
                    dic.Add("escqjlb", node.escqjlb);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(RetBody_DetailJson) };
                }
            }
        }
        #endregion

        #region 付款码收款格式化
        public class FkmskJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                interface_gjzh_fkmsk node = new interface_gjzh_fkmsk();
                object value = null;
                if (dictionary.TryGetValue("merId", out value))
                    node.merId = (string)value;
                if (dictionary.TryGetValue("subAppId", out value))
                    node.subAppId = (string)value;
                if (dictionary.TryGetValue("orderId", out value))
                    node.orderId = (string)value;
                if (dictionary.TryGetValue("authCode", out value))
                    node.authCode = (string)value;
                if (dictionary.TryGetValue("userId", out value))
                    node.userId = (string)value;
                if (dictionary.TryGetValue("termId", out value))
                    node.termId = (string)value;
                if (dictionary.TryGetValue("notifyUrl", out value))
                    node.notifyUrl = (string)value;
                if (dictionary.TryGetValue("txnAmt", out value))
                    node.txnAmt = (string)value;
                if (dictionary.TryGetValue("currencyCode", out value))
                    node.currencyCode = (string)value;
                if (dictionary.TryGetValue("body", out value))
                    node.body = (string)value;
                if (dictionary.TryGetValue("mchReserved", out value))
                    node.mchReserved = (string)value;
                if (dictionary.TryGetValue("tradeScene", out value))
                    node.tradeScene = (string)value;
                if (dictionary.TryGetValue("identity", out value))
                    node.identity = (string)value;
                if (dictionary.TryGetValue("policyNo", out value))
                    node.policyNo = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as interface_gjzh_fkmsk;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.merId))
                    dic.Add("merId", node.merId);
                if (!string.IsNullOrEmpty(node.subAppId))
                    dic.Add("subAppId", node.subAppId);
                if (!string.IsNullOrEmpty(node.orderId))
                    dic.Add("orderId", node.orderId);
                if (!string.IsNullOrEmpty(node.authCode))
                    dic.Add("authCode", node.authCode);
                if (!string.IsNullOrEmpty(node.userId))
                    dic.Add("userId", node.userId);
                if (!string.IsNullOrEmpty(node.termId))
                    dic.Add("termId", node.termId);
                if (!string.IsNullOrEmpty(node.notifyUrl))
                    dic.Add("notifyUrl", node.notifyUrl);
                if (!string.IsNullOrEmpty(node.txnAmt))
                    dic.Add("txnAmt", node.txnAmt);
                if (!string.IsNullOrEmpty(node.currencyCode))
                    dic.Add("currencyCode", node.currencyCode);
                if (!string.IsNullOrEmpty(node.body))
                    dic.Add("body", node.body);
                if (!string.IsNullOrEmpty(node.mchReserved))
                    dic.Add("mchReserved", node.mchReserved);
                if (!string.IsNullOrEmpty(node.tradeScene))
                    dic.Add("tradeScene", node.tradeScene);
                if (!string.IsNullOrEmpty(node.identity))
                    dic.Add("identity", node.identity);
                if (!string.IsNullOrEmpty(node.policyNo))
                    dic.Add("policyNo", node.policyNo);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(interface_gjzh_fkmsk) };
                }
            }
        }
        #endregion

        #region 付款码收款返回格式化
        public class FkmskretJSConverter : JavaScriptConverter
        {
            public override object Deserialize(IDictionary<string, object> dictionary, Type type, JavaScriptSerializer serializer)
            {
                interface_gjzh_fkmsk_ret node = new interface_gjzh_fkmsk_ret();
                object value = null;
                if (dictionary.TryGetValue("cmborderid", out value))
                    node.cmborderid = (string)value;
                if (dictionary.TryGetValue("txnamt", out value))
                    node.txnamt = (string)value;
                if (dictionary.TryGetValue("dscamt", out value))
                    node.dscamt = (string)value;
                if (dictionary.TryGetValue("paytype", out value))
                    node.paytype = (string)value;
                if (dictionary.TryGetValue("openid", out value))
                    node.openid = (string)value;
                if (dictionary.TryGetValue("tradestate", out value))
                    node.tradestate = (string)value;
                if (dictionary.TryGetValue("txntime", out value))
                    node.txntime = (string)value;
                if (dictionary.TryGetValue("enddate", out value))
                    node.enddate = (string)value;
                if (dictionary.TryGetValue("endtime", out value))
                    node.endtime = (string)value;
                return node;
            }
            public override IDictionary<string, object> Serialize(object obj, JavaScriptSerializer serializer)
            {
                Dictionary<string, object> dic = new Dictionary<string, object>();
                var node = obj as interface_gjzh_fkmsk_ret;
                if (node == null)
                    return null;
                if (!string.IsNullOrEmpty(node.cmborderid))
                    dic.Add("cmborderid", node.cmborderid);
                if (!string.IsNullOrEmpty(node.txnamt))
                    dic.Add("txnamt", node.txnamt);
                if (!string.IsNullOrEmpty(node.dscamt))
                    dic.Add("dscamt", node.dscamt);
                if (!string.IsNullOrEmpty(node.paytype))
                    dic.Add("paytype", node.paytype);
                if (!string.IsNullOrEmpty(node.openid))
                    dic.Add("openid", node.openid);
                if (!string.IsNullOrEmpty(node.tradestate))
                    dic.Add("tradestate", node.tradestate);
                if (!string.IsNullOrEmpty(node.txntime))
                    dic.Add("txntime", node.txntime);
                if (!string.IsNullOrEmpty(node.enddate))
                    dic.Add("enddate", node.enddate);
                if (!string.IsNullOrEmpty(node.endtime))
                    dic.Add("endtime", node.endtime);
                return dic;
            }
            public override IEnumerable<Type> SupportedTypes
            {
                get
                {
                    return new Type[] { typeof(interface_gjzh_fkmsk_ret) };
                }
            }
        }
        #endregion
        #endregion

        #region 字符处理
        public static T parse<T>(string JsonString)
        {
            using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(JsonString)))
            {
                return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(ms);
            }
        }

        public static string stringify(object JsonObject)
        {
            using (var ms = new MemoryStream())
            {
                new DataContractJsonSerializer(JsonObject.GetType()).WriteObject(ms, JsonObject);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        public static List<T> JsonStringToList<T>(string JsonStr)
        {
            JavaScriptSerializer Serializer = new JavaScriptSerializer();
            List<T> objs = Serializer.Deserialize<List<T>>(JsonStr);
            return objs;
        }

        public static T Deserialize<T>(string Json)
        {
            T obj = Activator.CreateInstance<T>();
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(Json)))
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(obj.GetType());
                return (T)serializer.ReadObject(ms);
            }
        }

        public static string String2Base64(string str)
        {
            byte[] byteBody = Encoding.UTF8.GetBytes(str);
            return (Convert.ToBase64String(byteBody));
        }
        #endregion

        #region 将datatable转换为json
        public static string Dtb2Json(DataTable dtb, string appid, string secret, string timestamp, string publickey, ref string apisign, ref string ls_biz)
        {
            string ls_sign_before1 = "";
            string ls_sign_before2 = "";
            string sign = "";
            string ls_content = "";
            string ls_content_old = "";
            string ls_memid = "";
            JavaScriptSerializer jss = new JavaScriptSerializer();
            System.Collections.ArrayList dic = new System.Collections.ArrayList();
            foreach (DataRow dr in dtb.Rows)
            {
                System.Collections.Generic.Dictionary<string, object> drow = new System.Collections.Generic.Dictionary<string, object>();
                foreach (DataColumn dc in dtb.Columns)
                {
                    if (dc.ColumnName == "MERID")
                    { dc.ColumnName = "merId";
                        ls_memid = dr[dc.ColumnName].ToString(); }
                    if (dc.ColumnName == "SUBAPPID")
                    { dc.ColumnName = "subAppId";
                        //if (string.IsNullOrEmpty(dr[dc.ColumnName].ToString()))
                        //{
                        //    continue;
                        //}
                    }
                    if (dc.ColumnName == "ORDERID")
                    { dc.ColumnName = "orderId"; }
                    if (dc.ColumnName == "AUTHCODE")
                    { dc.ColumnName = "authCode"; }
                    if (dc.ColumnName == "USERID")
                    { dc.ColumnName = "userId";
                        //if (string.IsNullOrEmpty(dr[dc.ColumnName].ToString()))
                        //{
                        //    continue;
                        //}
                    }
                    if (dc.ColumnName == "TERMID")
                    { dc.ColumnName = "termId"; }
                    if (dc.ColumnName == "NOTIFYURL")
                    { dc.ColumnName = "notifyUrl"; }
                    if (dc.ColumnName == "TXNAMT")
                    { dc.ColumnName = "txnAmt"; }
                    if (dc.ColumnName == "CURRENCYCODE")
                    { dc.ColumnName = "currencyCode";
                        //if (string.IsNullOrEmpty(dr[dc.ColumnName].ToString()))
                        //{
                        //    continue;
                        //}
                    }
                    if (dc.ColumnName == "BODY")
                    { dc.ColumnName = "body";
                        //if (string.IsNullOrEmpty(dr[dc.ColumnName].ToString()))
                        //{
                        //    continue;
                        //}
                    }
                    if (dc.ColumnName == "MCHRESERVED")
                    { dc.ColumnName = "mchReserved";
                        //if (string.IsNullOrEmpty(dr[dc.ColumnName].ToString()))
                        //{
                        //    continue;
                        //}
                    }
                    if (dc.ColumnName == "TRADESCENE")
                    { dc.ColumnName = "tradeScene";
                        if (string.IsNullOrEmpty(dr[dc.ColumnName].ToString()))
                        {
                            continue;
                        }
                    }
                    if (dc.ColumnName == "IDENTITY")
                    { dc.ColumnName = "identity";
                        if (string.IsNullOrEmpty(dr[dc.ColumnName].ToString()))
                        {
                            continue;
                        }
                    }
                    if (dc.ColumnName == "POLICYNO")
                    { dc.ColumnName = "policyNo";
                        if (string.IsNullOrEmpty(dr[dc.ColumnName].ToString()))
                                {
                            continue;
                        }}
                    if (dr[dc.ColumnName].ToString() == "" || dr[dc.ColumnName].ToString() == null)
                    {
                        drow.Add(dc.ColumnName, "");
                    }
                    else
                    {
                        drow.Add(dc.ColumnName, dr[dc.ColumnName]);
                    }
                }
                dic.Add(drow);
            }
            ls_content = (jss.Serialize(dic).Replace("[", "")).Replace("]", "");
            ls_content_old = ls_content;
            ls_content = ls_content.Replace("\"", "\\\"");
            ls_content = ls_content.Replace("@@@@@@@@", "\\\\\\\"");
            //序列化  
            ls_sign_before1 = "{\"" + dtb.TableName.ToString() + "\":\"" + ls_content + "\",\"encoding\":\"UTF-8\",";
            ls_sign_before2 = "\"signMethod\":\"01\"," + "\"version\":\"0.0.1\"" + "}";
            ls_biz = "biz_content=" + ls_content_old + "&encoding=UTF-8&signMethod=01&version=0.0.1";
            ls_biz = ls_biz.Replace("@@@@@@@@", "\\\"");
            if (!File.Exists(Environment.CurrentDirectory + "\\DBConn\\"+ ls_memid + ".pem"))
            {
                return "@@";
            }
            sign = RSASign(ls_biz, ls_memid);

            apisign = "appid=" + appid + "&secret=" + secret + "&sign=" + sign + "&timestamp=" + timestamp;
            apisign = UserMd5(apisign);
            return ls_sign_before1 + "\"sign\":\"" + sign + "\"," + ls_sign_before2;
        }
        #endregion

        #region 将json转换为DataTable
        public static DataTable JsonToDataTable(string strJson, string tablename)
        {
            //转换json格式
            strJson = strJson.Replace(",\"", "*\"").Replace("\":", "\"#").ToString();
            //取出表名   
            var rg = new Regex(@"(?<={)[^:]+(?=:\[)", RegexOptions.IgnoreCase);
            string strName = rg.Match(strJson).Value;
            DataTable tb = null;
            //去除表名   
            strJson = strJson.Substring(strJson.IndexOf("[") + 1);
            strJson = strJson.Substring(0, strJson.IndexOf("]"));

            //获取数据   
            rg = new Regex(@"(?<={)[^}]+(?=})");
            MatchCollection mc = rg.Matches(strJson);
            for (int i = 0; i < mc.Count; i++)
            {
                string strRow = mc[i].Value;
                string[] strRows = strRow.Split('*');

                //创建表   
                if (tb == null)
                {
                    tb = new DataTable();
                    tb.TableName = tablename;
                    foreach (string str in strRows)
                    {
                        var dc = new DataColumn();
                        string[] strCell = str.Split('#');

                        if (strCell[0].Substring(0, 1) == "\"")
                        {
                            int a = strCell[0].Length;
                            dc.ColumnName = strCell[0].Substring(1, a - 2);
                        }
                        else
                        {
                            dc.ColumnName = strCell[0];
                        }
                        tb.Columns.Add(dc);
                    }
                    tb.AcceptChanges();
                }

                //增加内容   
                DataRow dr = tb.NewRow();
                for (int r = 0; r < strRows.Length; r++)
                {
                    dr[r] = strRows[r].Split('#')[1].Trim().Replace("，", ",").Replace("：", ":").Replace("\"", "");
                }
                tb.Rows.Add(dr);
                tb.AcceptChanges();
            }
            return tb;
        }
        #endregion

        /// <summary>
        /// C#反射遍历对象属性
        /// </summary>
        /// <typeparam name="T">对象类型</typeparam>
        /// <param name="model">对象</param>
        public static DataTable ForeachClassProperties<T>(T model, DataTable dtinput, string ls_guid, string ls_func)
        {
            string ls_priname = "";
            DataTable dt = null;
            DataTable dtt = null;
            Type t = model.GetType();
            PropertyInfo[] PropertyList = t.GetProperties();
            if (dtinput == null || dtinput.Rows.Count < 1)
            {
                dt = new DataTable(t.Name);
                foreach (PropertyInfo item in PropertyList)
                {
                    dt.Columns.Add(item.Name, System.Type.GetType(HConvertByType(item.PropertyType)));
                    object[] objArray = item.GetCustomAttributes(false);
                    if (objArray.Length > 0)
                    {
                        if (((System.Runtime.Serialization.DataMemberAttribute)objArray[0]).IsRequired == true)
                            ls_priname = item.Name;
                        dt.PrimaryKey = new DataColumn[] { dt.Columns[ls_priname] };
                    }
                }
                dtt = dt;
            }
            else
            {
                dtt = dtinput;
                ls_priname = dtinput.PrimaryKey[0].ToString();
            }
            DataRow dr = dtt.NewRow();
            foreach (PropertyInfo item in PropertyList)
            {
                string name = item.Name;
                object value = item.GetValue(model, null);
                if (value == null)
                {
                    dr[name] = DBNull.Value;
                }
                else
                {
                    dr[name] = value;
                }
            }
            if (string.IsNullOrEmpty(dr[ls_priname].ToString()))
                dr[ls_priname] = ls_guid;
            dtt.Rows.Add(dr);
            return dtt;
        }
        #region 根据TYPE进行转换
        public static string HConvertByType(Type type)
        {
            Type valtype = type;
            string pptypeName = valtype.Name;
            string pname = valtype.Name;
            pptypeName = valtype.FullName;
            if (pname.LastIndexOf("Int") != -1)
            {
                return pptypeName;
            }
            else if (pname == "DateTime")
            {
                return pptypeName;
            }
            else if (pname == "String")
            {
                return pptypeName;
            }
            else if (pname == "Decimal")
            {
                return pptypeName;
            }
            else if (pname == "Nullable`1")
            {
                if (pptypeName.LastIndexOf("Int") != -1)
                {
                    return "System.Int32";
                }
                else if (pptypeName.LastIndexOf("DateTime") != -1)
                {
                    return "System.DateTime";
                }
                else if (pptypeName.LastIndexOf("String") != -1)
                {
                    return "System.String";
                }
                else if (pptypeName.LastIndexOf("Decimal") != -1)
                {
                    return "System.Decimal";
                }
            }
            return "NoDefintType";
        }
        #endregion

        #region 发送短信
        public static string GetHtmlFromUrl(string url)
        {
            string strRet = null;
            if (url == null || url.Trim().ToString() == "")
            {
                return "短信通讯地址为空";
            }
            string targeturl = url.Trim().ToString();
            try
            {
                HttpWebRequest hr = (HttpWebRequest)WebRequest.Create(targeturl);
                hr.UserAgent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)";
                hr.Method = "GET";
                hr.Timeout = 30 * 60 * 1000;
                WebResponse hs = hr.GetResponse();
                Stream sr = hs.GetResponseStream();
                StreamReader ser = new StreamReader(sr, Encoding.Default);
                strRet = ser.ReadToEnd();
            }
            catch (Exception ex)
            {
                return ex.Message.ToString();
            }
            return "TRUE";
        }
        #endregion

        #region 文件处理
        public static string UpFile(byte[] bt, string FilePath, string FileName)//上传
        {
            try
            {
                if (Directory.Exists(FilePath) == false)//如果不存在就创建file文件夹
                {
                    Directory.CreateDirectory(FilePath);
                }
                //else
                //{
                //    if (File.Exists(FileName + "\\" + FileName))
                //    {
                //        //存在文件
                //        File.Delete(FileName + "\\" + FileName);
                //    }
                //}
                MemoryStream m = new MemoryStream(bt);
                using (FileStream fs = File.Open(FilePath + "\\" + FileName, FileMode.Create))
                {
                    m.WriteTo(fs);
                    m.Close();
                    fs.Close();
                    return "TRUE";
                }
            }
            catch (Exception xx) { return xx.Message; }
        }

        public static byte[] DownFile(string FilePath)//下载
        {
            try
            {
                using (FileStream fs = File.Open(FilePath, FileMode.Open))
                {
                    byte[] bt = new byte[fs.Length];
                    fs.Read(bt, 0, Convert.ToInt32(fs.Length));
                    fs.Close();
                    return bt;
                }
            }
            catch { return null; }
        }
        #endregion

        #region 随机生成码
        private static char[] constant =
                      {
                        '0','1','2','3','4','5','6','7','8','9',
                        'A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y'
                      };

        public static string GenerateRandomNumber(long Length)
        {
            System.Text.StringBuilder newRandom = new System.Text.StringBuilder(33);
            Random rd = new Random();
            for (long i = 0; i < Length; i++)
            {
                newRandom.Append(constant[rd.Next(33)]);
            }
            return newRandom.ToString();
        }
        #endregion

        #region 字符串拼接
        public static string JsonChange(ArrayList ls_str)
        {
            string ls_json;
            ls_json = ls_str[0].ToString();
            for (int i = 1; i < ls_str.Count; i++)
            {
                ls_json = ls_json.Trim().Substring(0, ls_json.Trim().Length - 1) + "," + ls_str[i].ToString().Trim().Substring(1);
            }
            return ls_json;
        }
        #endregion

        #region 解析通讯密匙
        /*
		 * / <summary>
		 * / MD5 32位加密
		 * / </summary>
		 * / <param name="str"></param>
		 * / <returns></returns>
		 */
        public static string UserMd5(string str)
        {
            string cl = str;
            string pwd = "";
            MD5 md5 = MD5.Create(); /* 实例化一个md5对像 */
            /* 加密后是一个字节类型的数组，这里要注意编码UTF8/Unicode等的选择　 */
            byte[] s = md5.ComputeHash(Encoding.UTF8.GetBytes(cl));
            /* 通过使用循环，将字节类型的数组转换为字符串，此字符串是常规字符格式化所得 */
            for (int i = 0; i < s.Length; i++)
            {
                /* 将得到的字符串使用十六进制类型格式。格式后的字符是小写的字母，如果使用大写（X）则格式后的字符是大写字符 */
                pwd = pwd + s[i].ToString("X2");
            }
            return (pwd.ToLower());
        }

        #endregion

        #region sha256加密
        public static string sha256(string data)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            byte[] hash = SHA256Managed.Create().ComputeHash(bytes);

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                builder.Append(hash[i].ToString("X2"));
            }

            return builder.ToString();
        }
        #endregion

        #region base64
        ///编码
        public static string EncodeBase64(string code_type, string code)
        {
            string encode = "";
            byte[] bytes = Encoding.GetEncoding(code_type).GetBytes(code);
            try
            {
                encode = Convert.ToBase64String(bytes);
            }
            catch
            {
                encode = code;
            }
            return encode;
        }
        ///解码
        public static string DecodeBase64(string code_type, string code)
        {
            string decode = "";
            byte[] bytes = Convert.FromBase64String(code);
            try
            {
                decode = Encoding.GetEncoding(code_type).GetString(bytes);
            }
            catch
            {
                decode = code;
            }
            return decode;
        }
        #endregion

        #region RSA2加密
        public static string RSA2(string publickey, string plaintext)
        {
            RSACryptoServiceProvider rsaProvider = DecodeRSAPrivateKey(plaintext);
            String PrivateKey = rsaProvider.ToXmlString(true);

            RSACryptoServiceProvider rsa2 = new RSACryptoServiceProvider();
            rsa2.FromXmlString(PrivateKey);

            byte[] data = Encoding.UTF8.GetBytes(plaintext);
            byte[] endata = rsa2.SignData(data, "SHA256");
            return Convert.ToBase64String(endata);

            //rsa2开始加密   
            //byte[] cipherbytes;
            //cipherbytes = rsa2.Encrypt(Encoding.UTF8.GetBytes(plaintext),false);
            //return System.Text.Encoding.Default.GetString(cipherbytes);
        }

        public static RSACryptoServiceProvider DecodeRSAPrivateKey(string priKey)
        {
            //var privkey = Convert.FromBase64String(priKey);
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;


            // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
            //MemoryStream mem = new MemoryStream(privkey);
            //BinaryReader binr = new BinaryReader(mem);
            string path = @"D:\\project\\ConsoleApplication1\\li_pri.der";
            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);

            BinaryReader binr = new BinaryReader(fs);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();        //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();       //advance 2 bytes
                else
                    return null;


                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102) //version number
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    return null;




                //------  all private key components are Integer sequences ----
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);


                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);


                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);


                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);


                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);


                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);


                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);


                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);


                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAparams = new RSAParameters();
                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                RSA.ImportParameters(RSAparams);




                return RSA;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message + e.StackTrace);
                return null;
            }
            finally
            {
                binr.Close();
            }
        }

        public static string RSASign(string data,string ls_memid)
        {
            string signType = "RSA2";
            RSACryptoServiceProvider rsaCsp = LoadCertificateFile(PrivateKey+ ls_memid+ ".pem", signType);
            byte[] dataBytes = null;
            dataBytes = Encoding.UTF8.GetBytes(data);

            if ("RSA2".Equals(signType))
            {
                byte[] signatureBytes = rsaCsp.SignData(dataBytes, "SHA256");
                return Convert.ToBase64String(signatureBytes);
            }
            else
            {
                byte[] signatureBytes = rsaCsp.SignData(dataBytes, "SHA1");
                return Convert.ToBase64String(signatureBytes);
            }
        }
        public static string PrivateKey
        {
            get
            {
                //return AppDomain.CurrentDomain.BaseDirectory + "/Keys/rsa_private_key.pem";
                return Environment.CurrentDirectory + "\\DBConn\\";
            }
        }
        private static RSACryptoServiceProvider LoadCertificateFile(string filename, string signType)
        {
            using (System.IO.FileStream fs = System.IO.File.OpenRead(filename))
            {
                byte[] data = new byte[fs.Length];
                byte[] res = null;
                fs.Read(data, 0, data.Length);
                if (data[0] != 0x30)
                {
                    res = GetPem("RSA PRIVATE KEY", data);
                }
                try
                {
                    RSACryptoServiceProvider rsa = DecodeRSAPrivateKey(res, signType);
                    return rsa;
                }
                catch
                {
                    throw;
                }

            }
        }
        private static byte[] GetPem(string type, byte[] data)
        {
            string pem = Encoding.UTF8.GetString(data);
            string header = String.Format("-----BEGIN {0}-----\\n", type);
            string footer = String.Format("-----END {0}-----", type);
            int start = pem.IndexOf(header) + header.Length;
            int end = pem.IndexOf(footer, start);
            string base64 = pem.Substring(start, (end - start));

            return Convert.FromBase64String(base64);
        }

        private static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey, string signType)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // --------- Set up stream to decode the asn.1 encoded RSA private key ------
            MemoryStream mem = new MemoryStream(privkey);
            BinaryReader binr = new BinaryReader(mem);  //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();    //advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102) //version number
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    return null;


                //------ all private key components are Integer sequences ----
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);


                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                CspParameters CspParameters = new CspParameters();
                CspParameters.Flags = CspProviderFlags.UseMachineKeyStore;

                int bitLen = 1024;
                if ("RSA2".Equals(signType))
                {
                    bitLen = 2048;
                }

                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(bitLen, CspParameters);
                RSAParameters RSAparams = new RSAParameters();
                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                RSA.ImportParameters(RSAparams);
                return RSA;
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                return null;
            }
            finally
            {
                binr.Close();
            }
        }
        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)     //expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();    // data size in next byte
            else
                if (bt == 0x82)
            {
                highbyte = binr.ReadByte(); // data size in next 2 bytes
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;     // we already have the data size
            }

            while (binr.ReadByte() == 0x00)
            {   //remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);       //last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }

        public static string GetSignContent(IDictionary<string, string> parameters)
        {
            IDictionary<string, string> sortedParams = new SortedDictionary<string, string>(parameters);
            IEnumerator<KeyValuePair<string, string>> dem = sortedParams.GetEnumerator();

            StringBuilder query = new StringBuilder("");
            while (dem.MoveNext())
            {
                string key = dem.Current.Key;
                string value = dem.Current.Value;
                if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(value))
                {
                    query.Append(key).Append("=").Append(value).Append("&");
                }
            }
            string content = query.ToString().Substring(0, query.Length - 1);
            //content = RSASign(content);
            return content;
        }

        #endregion

        # region 获取时间戳
        public static string GetTimeStamp()
        {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(ts.TotalSeconds).ToString();
        }
        #endregion
    }
    /// <summary>
    /// Json帮助类
    /// </summary>
    public static class JsonHelper
    {
        /// <summary>
        /// 将对象序列化为JSON格式
        /// </summary>
        /// <param name="o">对象</param>
        /// <returns>json字符串</returns>
        public static string SerializeObject(object o)
        {
            string json = JsonConvert.SerializeObject(o);
            return json;
        }

        /// <summary>
        /// 解析JSON字符串生成对象实体
        /// </summary>
        /// <typeparam name="T">对象类型</typeparam>
        /// <param name="json">json字符串(eg.{"ID":"112","Name":"石子儿"})</param>
        /// <returns>对象实体</returns>
        public static T DeserializeJsonToObject<T>(string json) where T : class
        {
            JsonSerializer serializer = new JsonSerializer();
            StringReader sr = new StringReader(json);
            object o = serializer.Deserialize(new JsonTextReader(sr), typeof(T));
            T t = o as T;
            return t;
        }

        /// <summary>
        /// 解析JSON数组生成对象实体集合
        /// </summary>
        /// <typeparam name="T">对象类型</typeparam>
        /// <param name="json">json数组字符串(eg.[{"ID":"112","Name":"石子儿"}])</param>
        /// <returns>对象实体集合</returns>
        public static List<T> DeserializeJsonToList<T>(string json) where T : class
        {
            JsonSerializer serializer = new JsonSerializer();
            StringReader sr = new StringReader(json);
            object o = serializer.Deserialize(new JsonTextReader(sr), typeof(List<T>));
            List<T> list = o as List<T>;
            return list;
        }

        /// <summary>
        /// 反序列化JSON到给定的匿名对象.
        /// </summary>
        /// <typeparam name="T">匿名对象类型</typeparam>
        /// <param name="json">json字符串</param>
        /// <param name="anonymousTypeObject">匿名对象</param>
        /// <returns>匿名对象</returns>
        public static T DeserializeAnonymousType<T>(string json, T anonymousTypeObject)
        {
            T t = JsonConvert.DeserializeAnonymousType(json, anonymousTypeObject);
            return t;
        }
    }
}