using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Controls;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

namespace TestVS
{
    class Program
    {
        static void Main(string[] args)
        {
            string slash = "/";
            Config config = new ConfigurationBuilder()
          .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
          .AddJsonFile("Storage" + slash + "Config" + slash + "appsettings.json")
          .Build()
          .Get<Config>();

            LdapConnection ldapConn = new LdapConnection();
            ldapConn.SecureSocketLayer = false;

            Novell.Directory.Ldap.LdapSearchConstraints cons = ldapConn.SearchConstraints;
            cons.ReferralFollowing = true;
            ldapConn.Constraints = cons;

            ldapConn.Connect(config.Host, config.Port);
            var count = 0;
            var users = new Dictionary<string, string>();
            var listofUserFromAD = new List<ADUserModel>();

            ldapConn.Bind(config.UserName, config.Password);
            var groups = new Stack<string>();
            var uniqueGroups = new HashSet<string>();

            var constraints = new LdapSearchConstraints();
            constraints.SetControls(new LdapControl[]
            {
                            new LdapSortControl(new LdapSortKey("sn"), true),
                            new LdapVirtualListControl("sn=*", 0, 2000)
            });

            ILdapSearchResults searchResults = ldapConn.Search(
             "OU=Dotin,DC=dotin,DC=test",
               //distinguishedName,
               LdapConnection.ScopeSub,
                "(&(objectClass=user))",
                //"(&(objectCategory=person)(objectClass=user))",
                null,
                false,

                constraints
            );
            while (searchResults.HasMore())
            {
                count++;
                var nextEntry = searchResults.Next();

                nextEntry.GetAttributeSet();
                var attr = nextEntry.GetAttribute("NAME");

                if (attr == null)
                {
                    users.Add("Distinguished Name", nextEntry.GetAttribute("distinguishedName").StringValue);
                    //Console.WriteLine(users["distinguishedName"].ToString());
                }
                else
                {
                    users.Add((nextEntry.GetAttribute("SAMACCOUNTNAME") == null) ? "NULL ACC Name " + count : nextEntry.GetAttribute("SAMACCOUNTNAME").StringValue
                        , (nextEntry.GetAttribute("DISTINGUISHEDNAME") == null) ? "NULL DN" + count : nextEntry.GetAttribute("distinguishedName").StringValue);
                    //Console.WriteLine(nextEntry.GetAttribute("SAMACCOUNTNAME"));
                }
                string usereName = nextEntry.GetAttribute("sAMAccountName").StringValue;
                string time = nextEntry.GetAttribute("pwdLastSet").StringValue;
                long time1 = long.Parse(time);
                DateTime lastChangeDate = new DateTime(1601, 01, 01).AddTicks(time1);
                DateTime expireDate = lastChangeDate.AddYears(1);
                DateTime userExpireDate = DateTime.Today.AddDays(3);
                listofUserFromAD.Add(new ADUserModel() { userName = usereName, expireDate = expireDate });
                Console.WriteLine(count + " " + usereName + " ExpiredDate " + expireDate);


            }
            Console.WriteLine("Total Is " + count);
        }

    }
}