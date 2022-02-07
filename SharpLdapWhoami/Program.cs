using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices.Protocols;
using System.DirectoryServices.ActiveDirectory;
using System.Net;
using System.Security.Principal;

/*
 * Written by Jonas Vestberg (@bugch3ck)
 * Stolen from https://github.com/leechristensen/Random/blob/master/PowerShellScripts/Get-LdapCurrentUser.ps1
 */
namespace SharpLdapWhoami
{
    public struct Arguments
    {
        public enum AuthMethodEnum // Values in sync with System.DirectoryServices.Protocols.AuthType
        {
            Ntlm = 3,
            Nego = 2,
            Negotiate = 2,
            Kerb = 9,
            Kerberos = 9
        };

        public bool Valid { get; set; }
        public bool Verbose { get; set; }
        public bool Group { get; set; }
        public bool User { get; set; }
        public string Server { get; set; }
        public AuthMethodEnum AuthMethod { get; set; }

    }

    struct GroupInfo
    {
        public GroupInfo(string dn, string name, string sid)
        {
            DN = dn;
            Name = name;
            Sid = sid;
        }
        public string DN { get; set; }
        public string Name { get; set; }
        public string Sid { get; set; }

        public GroupInfo(SearchResultEntry entry)
        {
            DN = entry.Attributes["distinguishedName"][0].ToString();
            Name = entry.Attributes["sAMAccountName"][0].ToString();
            if (entry.Attributes["objectSid"][0].GetType() == typeof(System.Byte[]))
            {
                Sid = new SecurityIdentifier((byte[])entry.Attributes["objectSid"][0], 0).ToString();
            }
            else
            {
                // Strange case when objectSig contains a string with the SID bytes instead of a byte array.
                Sid = new SecurityIdentifier(Encoding.ASCII.GetBytes((string)entry.Attributes["objectSid"][0]), 0).ToString();
            }
        }
    }

    class Program
    {

        static private void PrintHelp()
        {
            Console.WriteLine(
@"

SharpLdapWhoami by @bugch3ck.

    WhoAmI by asking the LDAP service on a domain controller.
    Original idea from Lee Christensen's Get-LdapCurrentUser.ps1

Usage:

    SharpLdapWhoami [/all] [/user] [/groups] [/v] [/server:<ldap server>] [/h | /?]

Options:

    /u /user                  - Show detailed user information.
    /g /groups                - Show group information (primary group, member of and recursive group membership).
    /a /all                   - /user and /group combined.
    /v /verbose               - Show verbose output.
    /h /help /?               - Show this help.
    /s /server:<ldap server>  - The LDAP server to use (defaults to autoselect in user and computer context).
    /m /method:<auth type>    - The authentication method to use against the LDAP server.
               ntlm               NTLM
               kerb, kerberos     Kerberos
               nego, negotiate    Negotiate

Examples:

    SharpLdapWhoami
    SharpLdapWhoami /method:ntlm
    SharpLdapWhoami /method:kerb
    SharpLdapWhoami /all /server:dc01.e-corp.local
    SharpLdapWhoami /u /s:10.10.10.1:636 /m:nego


Credits to
    
");
        }

        static private Arguments ParseArgs(string[] args)
        {
            Arguments parsedArgs = new Arguments() {
                Valid = true,
                AuthMethod=Arguments.AuthMethodEnum.Negotiate 
            };

            foreach (string arg in args)
            {
                string[] x = arg.Split(new char[] { ':' }, 2);
                string opt = x[0];
                string val = (x.Length > 1) ? x[1] : null;
                switch (opt)
                {
                    case "/v":
                    case "/verbose":
                        parsedArgs.Verbose = true;
                        break;
                    case "/u":
                    case "/user":
                        parsedArgs.User = true;
                        break;
                    case "/g":
                    case "/groups":
                        parsedArgs.Group = true;
                        break;
                    case "/a":
                    case "/all":
                        parsedArgs.User = true;
                        parsedArgs.Group = true;
                        break;
                    case "/s":
                    case "/server":
                        parsedArgs.Server = val;
                        break;
                    case "/m":
                    case "/method":
                        try
                        {
                            parsedArgs.AuthMethod = (Arguments.AuthMethodEnum) System.Enum.Parse(typeof(Arguments.AuthMethodEnum), val, true);

                        } catch (Exception)
                        {
                            Console.Error.WriteLine($"Error: Unknown authentication method {val}");
                            parsedArgs.Valid = false;
                        }

                        break;
                    default:
                        parsedArgs.Valid = false;
                        break;
                }
            }

            return parsedArgs;
        }

        static private void OutputResultTable(string title, string[] headings, GroupInfo entry)
        {
            Dictionary<string, GroupInfo> list = new Dictionary<string, GroupInfo>();
            list.Add(entry.DN, entry);
            OutputResultTable(title, headings, list);
        }

        static private void OutputResultTable(string title, string[] headings, Dictionary<string, GroupInfo> list)
        {
            Console.WriteLine();
            Console.WriteLine(title.ToUpper());
            Console.WriteLine(new String('-', title.Length));
            Console.WriteLine();

            int[] maxWidth = new int[] { 
                headings[0].Length, 
                headings[1].Length, 
                headings[2].Length 
            };

            foreach (GroupInfo entry in list.Values)
            {
                maxWidth[0] = (entry.Name.Length > maxWidth[0]) ? entry.Name.Length : maxWidth[0];
                maxWidth[1] = (entry.Sid.Length > maxWidth[1]) ? entry.Sid.Length : maxWidth[1];
                maxWidth[2] = (entry.DN.Length > maxWidth[2]) ? entry.DN.Length : maxWidth[2];
            }
            Console.WriteLine(
                String.Format("{0} {1} {2}",
                    headings[0].PadRight(maxWidth[0]),
                    headings[1].PadRight(maxWidth[1]),
                    headings[2].PadRight(maxWidth[2])
                )
            );
            Console.WriteLine(
                String.Format("{0} {1} {2}",
                    "".PadRight(maxWidth[0], '='),
                    "".PadRight(maxWidth[1], '='),
                    "".PadRight(maxWidth[2], '=')
                )
            );
            foreach (GroupInfo groupInfo in list.Values)
            {
                Console.WriteLine(
                    String.Format("{0} {1} {2}",
                        groupInfo.Name.PadRight(maxWidth[0]),
                        groupInfo.Sid.PadRight(maxWidth[1]),
                        groupInfo.DN.PadRight(maxWidth[2])
                    )
                );
            }

            Console.WriteLine();
        }

        static private void OutputVerbose(string s, bool isError = false)
        {
            if (ParsedArgs.Verbose == false) return;

            if (isError)
            {
                Console.Error.WriteLine($"[-] {s}");
            }
            else
            {
                Console.WriteLine($"[*] {s}");
            }
        }

        private static void AddGroupsInGroups(Dictionary<string,GroupInfo>groups, LdapConnection c, SearchRequest searchRequest)
        {
            // Get group information
            SearchResponse searchResponse = (SearchResponse)c.SendRequest(searchRequest);

            for (int i = 0; i < searchResponse.Entries.Count; i++)
            {
                GroupInfo groupInfo = new GroupInfo(searchResponse.Entries[i]);
                if (groups.ContainsKey(groupInfo.DN) == false)
                {
                    groups.Add(groupInfo.DN, groupInfo);

                    // Query groups that this group is a member of.
                    SearchRequest searchRequest2 = new SearchRequest
                        (
                        searchRequest.DistinguishedName,
                        $"(&(objectClass=group)(member={groupInfo.DN}))",
                        System.DirectoryServices.Protocols.SearchScope.Subtree,
                        new string[] { "sAMAccountName", "objectSid", "distinguishedName" }
                        );
                    AddGroupsInGroups(groups, c, searchRequest2);
                }
            }


        }

        public static Arguments ParsedArgs;

        static int Main(string[] args)
        {
            ParsedArgs = ParseArgs(args);
            Dictionary<string, GroupInfo> groups = new Dictionary<string, GroupInfo>();

            if (ParsedArgs.Valid == false)
            {
                PrintHelp();
                return -1; 
            }

            string server = ParsedArgs.Server;
            if (server == null)
            {
                OutputVerbose("No server argument. Using current context to find domain controller.");
                try
                {
                    OutputVerbose("Looking up domain controller for current user.");
                    Domain domain = Domain.GetCurrentDomain();
                    server = domain.FindDomainController().Name;
                }
                catch (Exception)
                {
                    OutputVerbose("Cannot retrieve domain controller for current user.", true);
                }
                if (server == null)
                {
                    try
                    {
                        OutputVerbose("Looking up domain controller for computer.");
                        Domain domain = Domain.GetComputerDomain();
                        server = domain.FindDomainController().Name;
                    }
                    catch (Exception)
                    {
                        OutputVerbose("Cannot retrieve domain controller for computer.", true);
                    }
                    if (server  == null)
                    {
                        Console.Error.WriteLine("Error: No ldap server specified and could not find a domain controller in user or computer context. Quitting");
                        return -2;
                    }
                }
            }

            LdapConnection c;
            c = new LdapConnection(server); // Defaults to AuthType.Negotiate
            c.AuthType = (System.DirectoryServices.Protocols.AuthType)ParsedArgs.AuthMethod;
            string response;

            try
            {
                ExtendedRequest extreq = new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");
                ExtendedResponse extres = (ExtendedResponse) c.SendRequest(extreq);
                response = Encoding.ASCII.GetString(extres.ResponseValue);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Error: Cannot connect to LDAP server ({e.Message})");
                return -10;
            }

            if (response == null)
            {
                Console.Error.WriteLine("Error: Failed to request current user from LDAP.");
            }
            else if (response.StartsWith("u:") == false)
            {
                Console.Error.WriteLine($"Error: Unexpected username format from LDAP ({response}).");
                return -1;
            }
            int i1 = response.IndexOf(':');
            int i2 = response.IndexOf('\\',i1+1);
            string userDomain = response.Substring(i1+1,i2-(i1+1)).ToLower(); // Conform with built in WHOAMI.exe
            string userName = response.Substring(i2+1);

            SearchRequest searchRequest;
            SearchResponse searchResponse;

            // Get domain DN to use as base in searches.
            searchRequest = new SearchRequest
                (
                "", 
                "(objectClass=*)", 
                System.DirectoryServices.Protocols.SearchScope.Base, 
                new string[] { "DefaultNamingContext" }
                );

            searchResponse = (SearchResponse) c.SendRequest(searchRequest);
            string baseDN = searchResponse .Entries[0].Attributes["DefaultNamingContext"][0].ToString();

            // Get user attributes
            searchRequest = new SearchRequest
                (
                baseDN, 
                $"(&(objectClass=user)(sAMAccountName={userName}))", 
                System.DirectoryServices.Protocols.SearchScope.Subtree, 
                new string[] { "objectSid", "primaryGroupID", "distinguishedName" }
                );
            searchResponse = (SearchResponse)c.SendRequest(searchRequest);

            SecurityIdentifier userSid = new SecurityIdentifier( (byte[])searchResponse.Entries[0].Attributes["objectSid"][0], 0);
            string userDN = searchResponse.Entries[0].Attributes["distinguishedName"][0].ToString();
            string userDomainSid = userSid.AccountDomainSid.ToString();
            string userPrimaryGroup = searchResponse.Entries[0].Attributes["primaryGroupID"][0].ToString();

            if ((ParsedArgs.User == false) && (ParsedArgs.Group == false))
            {
                Console.WriteLine($"{userDomain}\\{userName}");
            }
            else if (ParsedArgs.User) 
            {
                OutputResultTable("User information", new string[] { "User Name", "SID", "Distinguished Name" }, new GroupInfo(userDN, userName, userSid.ToString()));
            }

            // Get primary group information
            searchRequest = new SearchRequest
                (
                baseDN,
                $"(&(objectClass=group)(objectSid={userDomainSid}-{userPrimaryGroup}))",
                System.DirectoryServices.Protocols.SearchScope.Subtree,
                new string[] { "sAMAccountName", "objectSid", "distinguishedName" }
                );
            searchResponse = (SearchResponse)c.SendRequest(searchRequest);

            GroupInfo primaryGroupInfo = new GroupInfo(searchResponse.Entries[0]);

            groups.Add(primaryGroupInfo.DN, primaryGroupInfo);

            if (ParsedArgs.Group)
            {
                // Get group information
                searchRequest = new SearchRequest
                    (
                    baseDN,
                    $"(&(objectClass=group)(member={userDN}))",
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    new string[] { "sAMAccountName", "objectSid", "distinguishedName" }
                    );
                AddGroupsInGroups(groups, c, searchRequest);

                OutputResultTable("Group information", new string[] { "Group Name", "SID", "Distinguished Name" }, groups);
            }
            return 0;
        }
    }
}
