using System;
using System.Collections.Generic;
using System.Text;
using CyberArk.PasswordVault.PublicInterfaces;
using System.Xml;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using HttpUtils;
using Newtonsoft.Json;

//Start process (powershell)
using System.Diagnostics;


// TODO: Change the namespace
namespace CyberArk.Samples
{
    /// <summary>
    /// A sample implementation of the ITicketValidator interface.
    /// This class should inherit from ITicketValidator.
    /// TODO: Change the class name
    /// </summary>
    public class MyTicketingValidator : ITicketVaildatorEx
    {
        #region ITicketVaildatorEx Members


        #region Public Parameters
        //set Ticketing Parameters
        public string ticketingOutputUserMessage = string.Empty;
        public string paramHashApp = string.Empty;
        public string paramAPIHash = string.Empty;
        public string checkParameters = string.Empty;
        public string ModuleDirectory = string.Empty;
        public string paramAPIName = string.Empty;
        public string paramBypassID = string.Empty;
        public string paramAPIURL = string.Empty;

        //set Info from CyberArk
        public string cArkRequester = string.Empty;
        public string cArkPolicyID = string.Empty;
        public string cArkObjectName = string.Empty;
        public string cArkSafeName = string.Empty;
        public string cArklogonID = string.Empty;
        public string cArklogonPassword = string.Empty;

        //set error messages
        public string msgInvalidHash = string.Empty;
        public string msgInvalidTicket = string.Empty;
        public string msgBlankTicket = string.Empty;
        public string msgUnableToConnect = string.Empty;

        //set audit log
        public string auditLog = string.Empty;

        #endregion

        /// <summary>
        /// This method is called by PVWA when a password object is requested and the request
        /// needs to be validated against a ticketing system.
        /// Two different scenarios are demonstrated below:      
        /// First scenario: The ticket ID specified by the user is validated by the ticketing system.
        /// Second scenario: Based on parameters sent to this integration module, the ticketing system creates a new ticket ID and returns the ID to the PVWA. 
        /// </summary>
        /// <param name="parameters">Details about the request and the requesting user</param>
        /// <param name="ticketingOutput">Out parameter: Will contain the information returned to the PVWA.</param>
        /// <returns>This method must return ‘true’ if the ticket validation succeeds or ‘false’ if it fails.
        /// In case of success, the user will be able to access the requested password.</returns>

        
        public bool ValidateTicket(IValidationParametersEx parameters, out ITicketOutput ticketingOutput)
        {
            bool rc;
            bool bValid = false; // Validation result (the return value) - will contain true if validate succeed, false otherwise
            ticketingOutput = new TicketOutput();

            XmlNode xmlParameters = parameters.XmlNodeParameters;
            string[] internalParameters;
            ParseXmlParameters(xmlParameters, out internalParameters); //Kept the default ParseXML input & output. But parameters are parse to the public variables(not using "internalParameters")


            ITicketingConnectionAccount connectionAccount = parameters.TicketingConnectionAccount;
            string ticketingSystemName = parameters.SystemName;

            string returnedTicketId = parameters.TicketId;
            cArkRequester = parameters.RequestingUser;
            cArkPolicyID = parameters.PolicyId;
            cArkObjectName = parameters.ObjectName;
            cArkSafeName = parameters.SafeName;
            cArklogonID = parameters.TicketingConnectionAccount.UserName;
            cArklogonPassword = parameters.TicketingConnectionAccount.Password;

            /****************************************************************************************
             * Writing to the debug log - below is a sample showing how to access the debug log object and 
             * use it to write log records. Any information written to the debug log will show up in the application's log file
             * 
             */
            IDebugLog log = (IDebugLog)parameters;
            log.LogWrite("This is a log message from the ticketing system validator module.");

            /****************************************************************************************
             * First scenario
             * --------------
             * The parameters collection allows you to retrieve information about the calling user and the 
             * current request. You can scrutinize the parameters collection to determine whether 
             * to deny or approve the user's request.
             * A classic and simple scenario is to check the TicketId provided by the user
             * against the ticketing system and decide whether it is valid or not.
             * 
             */


            //Logon to the ticketing system:
            if (connectionAccount != null)
            {
                string ticketingSystemAddress = parameters.TicketingConnectionAccount.Address;
                string ticketingSystemUsername = parameters.TicketingConnectionAccount.UserName;
                string ticketingSystemPassword = parameters.TicketingConnectionAccount.Password;

                rc = LogonToTicketingSystem(ticketingSystemAddress, ticketingSystemUsername, ticketingSystemPassword);
                //TODO: Decide what to do if ticketing system is unavailable. You can still return a success code and include this information in ticketingOutput.TicketAuditOutput
                //ticketingOutput.UserMessage = OutputLog(parameters.TicketId);

            }
            else
            {
                //TODO: Replace with an appropriate denial/error message
                ticketingOutput.UserMessage = "No ticketing system login account was specified";
                return bValid;
            }



            //Complete the code that verifies the ticket ID against the ticketing system:
            bValid = CheckTicketIdValidity(parameters.TicketId, internalParameters); //TODO: Create a function that implements the validation
            //bValid = false;


            if (!bValid)
            {
                //TODO: Replace with an appropriate denial/error message
                ticketingOutput.UserMessage = ticketingOutputUserMessage;
            }
            else
            {
                ticketingOutput.TicketId = returnedTicketId; // Return the validated ticket ID
                ticketingOutput.TicketAuditOutput = string.Format("{0},{1}", returnedTicketId, auditLog); // Specify any additional information you'd like written to the audit log
            }

            return bValid;


            /****************************************************************************************
            * Second scenario
            * ---------------
            * Another common scenario is to create a new TicketId and return it to PVWA.
            * In this example, the parameters collection is passed to the method calling the ticketing system.
            * According to the parameters, the ticketing system issues a ticket ID and returns it to the PVWA.
            * 
            */
            /*

            //TODO: Replace with ticketing system interaction
            returnedTicketId = CreateTicketIdUsingTicketingSystem(parameters);

            ticketingOutput.TicketId = returnedTicketId; // Return the newly created ticket ID
            ticketingOutput.TicketAuditOutput = "Additional auditing information"; // Specify any additional information you'd like written to the audit log
            bValid = true;

            return bValid;
            */

        }

        //TODO: Implement the following functions:

        private string CreateTicketIdUsingTicketingSystem(IValidationParametersEx parameters)
        {
            return string.Empty;
        }

        private bool CheckTicketIdValidity(string ticketID, string[] internalParameters)
        {
            try 
            {
                //Validate if the current APP matches the HASH in PVWA parameters
                
                string ScriptHash = getHash(paramAPIName, paramHashApp);

                if (!(validateHash(ScriptHash, paramAPIHash)))
                {
                    ticketingOutputUserMessage = msgInvalidHash;
                    return false;
                }

                // if matching BypassID, returns true
                if (ticketID.Trim().ToUpper() == paramBypassID.Trim().ToUpper())
                {
                    auditLog = auditLog + " " + "TicketID matches the BypassID.";
                    return true;
                }
                else 
                {
                    // Here is the validation process. 

                    // If want to invoke powershell script
                     
                    ProcessStartInfo validation = new ProcessStartInfo();
                    validation.FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe";
                    validation.UseShellExecute = false;
                    validation.RedirectStandardOutput = true;
                    validation.Arguments = Path.Combine(ModuleDirectory, "ticket.ps1") + " " + en64(ticketID) + " " + en64(paramAPIURL) + " " + en64(cArkRequester) + " " + en64(cArkObjectName);
                    //Process.Start(validation);

                    {
                        using (Process processGetTixInfo = Process.Start(validation))
                        {
                            string validationResult = string.Empty;
                            using (StreamReader readerTask = processGetTixInfo.StandardOutput) validationResult = readerTask.ReadLine();
                            if (validationResult.Trim().ToUpper() == "VALID")
                            {
                                return true;
                            }
                            else
                            {
                                ticketingOutputUserMessage = msgInvalidTicket;
                                return false;
                            }
                        }
                    }
                    

                    /** If want to call restapi directly from dll
                     * 
                     * 
                    var client = new RestClient(@"https://comp2.jhdomain.com/AIMWebService/api/Accounts");
                    
                    var json = client.MakeRequest(@"?AppID=Sample&Query=Object=ticketing-dummy");
                    dynamic respond = JsonConvert.DeserializeObject(json);
                    string ValidID = respond.TicketID;

                    if (ticketID.Trim().ToUpper() == ValidID.Trim().ToUpper())
                    {
                        return true;
                    }
                    else
                    {
                        ticketingOutputUserMessage = ValidID;
                        return false;
                    }
                    */

                    return true;
                }

                //return true;
            }
            catch (Exception ex)
            {
                ticketingOutputUserMessage = ex.Message;
                return false;
            }

        }

        private bool LogonToTicketingSystem(string ticketingSystemAddress, string ticketingSystemUsername, string ticketingSystemPassword)
        {
            return true;
        }

        //#####################################################################################
        //common methods and functions
        //#####################################################################################
        string getHash(string Item, string HashApp)
        {
            //starts to get ticket info based on api return results
            ProcessStartInfo startGetHash = new ProcessStartInfo();
            startGetHash.FileName = Path.Combine(ModuleDirectory, HashApp);
            startGetHash.UseShellExecute = false;
            startGetHash.RedirectStandardOutput = true;
            startGetHash.Arguments = "gethash /filepath " + Path.Combine(ModuleDirectory,Item);
            {
                using (Process processGetTixInfo = Process.Start(startGetHash))
                {
                    string hashResult = string.Empty;
                    using (StreamReader readerTask = processGetTixInfo.StandardOutput) hashResult = readerTask.ReadLine();
                    //hash will contain a fixed 40 characters
                    hashResult = hashResult.Substring(0, 40);
                    return hashResult;
                }
            }
        }

        private string OutputLog(string Log)
        {
            //starts to get ticket info based on api return results
            ProcessStartInfo GenLog = new ProcessStartInfo();
            GenLog.FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe";
            GenLog.UseShellExecute = false;
            GenLog.RedirectStandardOutput = true;
            GenLog.Arguments = Path.Combine(ModuleDirectory,"ticket.ps1") + " '" + Log + "'";
            Process.Start(GenLog);

            {
                using (Process processGetTixInfo = Process.Start(GenLog))
                {
                    string LogResult = string.Empty;
                    using (StreamReader readerTask = processGetTixInfo.StandardOutput) LogResult = readerTask.ReadLine();
                    //hash will contain a fixed 40 characters
                    //hashResult = hashResult.Substring(0, 40);
                    return LogResult;
                }
            }
            
            
        }

        bool validateHash(string apiHash, string pAPIHash)
        {
            if (apiHash.Trim().ToUpper() == pAPIHash.Trim().ToUpper())
            {
                return true;
            }
            else if(pAPIHash.Trim().ToUpper() == "NULL")
            {                
                return true;
            }
            else
            {
                return false;
            }
        }

        // base64 encode
        private string en64(string input)
        {
            return (System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(input)));
        }




        /// <summary>
        /// The function will extract the relevant parameters values
        /// from the input parameters (xml structure)
        /// </summary>
        /// <param name="xmlParameters">Input parameters to extract</param>
        /// <param name="paramtersArray">Out parameter: will contain all the relevant parameters extracted from the input xml.</param>
        private void ParseXmlParameters(XmlNode xmlParameters, out string[] paramtersArray)
        {
            //get the ticketing parameters from PVWA
            checkParameters = xmlParameters.InnerXml;
            Match match1 = Regex.Match(checkParameters, "APIHash\" Value=\"([A-Za-z0-9]+)\"");
            paramAPIHash = match1.Groups[1].Value;
            Match match2 = Regex.Match(checkParameters, "msgInvalidHash\" Value=\"(.*?)\"");
            msgInvalidHash = match2.Groups[1].Value;
            Match match3 = Regex.Match(checkParameters, "msgUnableToConnect\" Value=\"(.*?)\"");
            msgUnableToConnect = match3.Groups[1].Value;
            Match match4 = Regex.Match(checkParameters, "HashApp\" Value=\"(.*?)\"");
            paramHashApp = match4.Groups[1].Value;
            Match match5 = Regex.Match(checkParameters, "msgInvalidTicket\" Value=\"(.*?)\"");
            msgInvalidTicket = match5.Groups[1].Value;
            Match match6 = Regex.Match(checkParameters, "msgBlankTicket\" Value=\"(.*?)\"");
            msgBlankTicket = match6.Groups[1].Value;
            Match match7 = Regex.Match(checkParameters, "ModuleDirectory\" Value=\"(.*?)\"");
            ModuleDirectory = match7.Groups[1].Value;
            Match match8 = Regex.Match(checkParameters, "APIName\" Value=\"(.*?)\"");
            paramAPIName = match8.Groups[1].Value;
            Match match9 = Regex.Match(checkParameters, "BypassID\" Value=\"(.*?)\"");
            paramBypassID = match9.Groups[1].Value;
            Match match10 = Regex.Match(checkParameters, "APIURL\" Value=\"(.*?)\"");
            paramAPIURL = match10.Groups[1].Value;

            //not using parametersArray
            paramtersArray = null;
        }


        /// <summary>
        /// Please do not remove - Obsolete (prior V5.5 ValidateTicket function) – for backward compatibility only     
        /// </summary>
        /// <param name="parameters">Details about the request and the requesting user</param>
        /// <param name="returnedMessage">Out parameter: A message to display to the user</param>
        /// <param name="returnedTicketId">Out parameter: The valid TicketId (may be created by this method)</param>
        /// <returns></returns>
        public bool ValidateTicket(IValidationParameters parameters, out string returnedMessage, out string returnedTicketId)
        {
            throw new NotImplementedException("Obsolete");
        }


        #endregion

    }
}
