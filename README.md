# Unknown-Reputation-Check
Using this tool we can check the reputation of IPAddress, Domains, Urls, Hashes and FileScan from the famous and well known Threat Intelligence websites.
 This tool provides Command Line Interface (CLI) to user. Famous Threat Intelligence websites are used in this tool (IBM X Force, IPVoid, VirusTotal, CiscoTalos, IPLocation)
 
 
### Script Execution:
Open command prompt and run the file using the command **python Main.py --parameter parametervalue -websitename**
Take an overview of commands available for this tool<br/>
**--help, -h** 	&nbsp; &nbsp; &nbsp; &nbsp; &nbsp;	show the list of all commands (show help message and exit)<br/>
**--ip**	&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&nbsp; 		Choose IPAddress as Parameter<br/>
**--domain** &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; Choose Domain as Parameter<br/>
**--url**	&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;		Choose Url as Parameter<br/>
**--hash**	&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;		Choose Hash as Parameter<br/>
**--filescan** &nbsp;&nbsp;&nbsp;&nbsp; &nbsp; &nbsp;		Choose FileScan as Parameter <br/>
**-ibm**  &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;  Choose IBM X Force to check the Malicoius data for IPAddress, Domain, Url and Hash<br/>
**-ipvoid** &nbsp; &nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;   Choose IPVoid to check IPAddress Reputation<br/>
**-talos** &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&nbsp;  Choose Cisco Talos to Check the Reputation of IPAddress, Domain, Url<br/>
**-virustotal** &nbsp; &nbsp; &nbsp; &nbsp;  Choose VirusTotal to get the Complete report of Url, Hash and FileScan<br/>
**-csv** &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;  &nbsp; &nbsp; Upload csv file for bulk check<br/>
**-location** &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; Check the location of the IPAddress<br/>
**-view** &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;&nbsp;	Choose a view in google maps where exact the location of IPAddress<br/>
**-all** &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&nbsp; Check the Reputation of IPAddress, Domain, Url and Hash from all the websites<br/>
