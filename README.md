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

### Examples:
**IPAddress Reputation Check**<br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -ibm<br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -ibm &nbsp;  -csv&nbsp; _csvfilepath_ <br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -ipvoid<br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -ipvoid &nbsp; -csv&nbsp; _csvfilepath_<br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -talos<br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -talos &nbsp; -csv&nbsp; _csvfilepath_<br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -location<br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -location &nbsp; -csv&nbsp; _csvfilepath_<br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -location -view <br/>
- python &nbsp; Main.py &nbsp; --ip &nbsp; xx.xx.xx.xx(_IPAddress_)&nbsp;  -view <br/>

**Domain Reputation Check**<br/>
- python &nbsp; Main.py &nbsp; --domain &nbsp; _domain name_&nbsp;  -ibm<br/>
- python &nbsp; Main.py &nbsp; --domain &nbsp; _domain name_&nbsp;  -ibm &nbsp; -csv&nbsp; _csvfilepath_<br/>
- python &nbsp; Main.py &nbsp; --domain &nbsp; _domain name_&nbsp;  -talos<br/>
- python &nbsp; Main.py &nbsp; --domain &nbsp; _domain name_&nbsp;  -talos &nbsp; -csv&nbsp; _csvfilepath_<br/>

**Url Reputation Check**<br/>
- python &nbsp; Main.py &nbsp; --url &nbsp; _url_&nbsp; -ibm<br/>
- python &nbsp; Main.py &nbsp; --url &nbsp; _url_&nbsp; -ibm &nbsp; -csv&nbsp; _csvfilepath_<br/>
- python &nbsp; Main.py &nbsp; --url &nbsp; _url_&nbsp; -talos<br/>
- python &nbsp; Main.py &nbsp; --url &nbsp; _url_&nbsp; -talos &nbsp; -csv&nbsp; _csvfilepath_<br/>
- python &nbsp; Main.py &nbsp; --url &nbsp; _url_&nbsp; -virustotal<br/>
- python &nbsp; Main.py &nbsp; --url &nbsp; _url_&nbsp; -virustotal &nbsp; -csv&nbsp; _csvfilepath_<br/>

**Hash Reputation Check**<br/>
- python &nbsp; Main.py &nbsp; --hash &nbsp; _hash(md5/sha256/sha1)_&nbsp; -ibm<br/>
- python &nbsp; Main.py &nbsp; --hash &nbsp; _hash(md5/sha256/sha1)_&nbsp; -ibm &nbsp; -csv&nbsp; _csvfilepath_<br/>
- python &nbsp; Main.py &nbsp; --hash &nbsp; _hash(md5/sha256/sha1)_&nbsp; -virustotal<br/>
- python &nbsp; Main.py &nbsp; --hash &nbsp; _hash(md5/sha256/sha1)_&nbsp; -virustotal &nbsp; -csv&nbsp; _csvfilepath_<br/>

**FileScan**<br/>
- python &nbsp; Main.py &nbsp; --filescan &nbsp; _filename_&nbsp; -virustotal<br/>

### Requirements
**IBM X Force**
: IBM X Force Provides an API to get the Reputation details of IPAddress, Domains, Urls and Hashes. <br/>
 - _Public API_:<br/>
   - Login to IBM X Force and get the API KEY and API PASSWORD<br/>
   - Add API KEY and API PASSWORD to Config text file<br/>
   - Public API provides limit of 5000 API Calls per month<br/>
- _Private API_:<br/>
   - If you are interested to buy an API Key Login to IBM X Force and Contact the experts to know the Price and Limit of API KEY<br/>

**VirusTotal**
: VirusTotal Provides an API to get the Reputation details of Urls, Hashes and FileScan. <br/>
 - _Public API_:<br/>
   - Login to VirusTotal and get the API KEY<br/>
   - Add API KEY to Config text file><br/>
   - Public API provides 4 API Calls per minute<br/>
 - _Private API_:<br/>
   - If you are interested to buy an API KEY Login to VirusTotal and Contact the experts to know the price and Limit of API<br/>
   
**CISCO Talos**
: CISCO Talos doesn't provide any APIs but we can do we scrapping using Beautifulsoup.<br/>
 - Selenium:<br/>
   - Selenium is used for Automation testing. In our case we it is used to extract the webpage content (page source code)<br/>
   - After getting page source code we will filter the required data<br/>
   - download the selenium webdriver(only chrome drivers are supported) from google and give the path in Config.txt file


