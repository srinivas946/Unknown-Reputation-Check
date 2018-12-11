import argparse, datetime
from Sources import VirusTotal, CiscoTalos, IPVoid, IBMXForce, IPLocation, All_Sites
from Config import Config

# -------------------------------------------------------------------
#   MAIN CLASS FOR IPADDRESS / DOMAIN / URL / HASH / FILESCAN CHECKS
# -------------------------------------------------------------------
class UREngine:

    def CLI(self):
        parse = argparse.ArgumentParser()
        parse.add_argument('--ip', nargs='?', const=1, help='IPAddress')
        parse.add_argument('--domain', nargs='?', const=1, help='Domain')
        parse.add_argument('--url', nargs='?', const=1, help='Url')
        parse.add_argument('--hash', nargs='?', const=1, help='Hash Value (MD5/SHA256/SHA1)')
        parse.add_argument('--filescan', nargs='?', const=1, help='File Scan, for multiple filescan store the filepaths in one csv file')
        parse.add_argument('--virus', nargs='?', const=1, help='Virus Check (Type of Virus and Risk)')
        parse.add_argument('-ibm', nargs='?', const=1, help='IBM X Force (IPAddress / Domains / Urls / Hashes (MD5, SHA256, SHA1))')
        parse.add_argument('-ipvoid', nargs='?', const=1, help='IPVoid (IPAddress)')
        parse.add_argument('-talos', nargs='?', const=1, help='Cisco Talos (IPAddress / Domains/ Urls) ')
        parse.add_argument('-virustotal', nargs='?', const=1, help='Virus Totoal (UrlCheck / HashCheck / FileScan)')
        parse.add_argument('-csv', nargs='?', const=1, help='csv file read for checks  realted to IPAddress / Domains / Urls / FileScan / hashchecks')
        parse.add_argument('-location', nargs='?', const=1, help='IPLocation (COUNTRY / CITY / ISP / LATITUDE / LONGITUDE)')
        parse.add_argument('-view', nargs='?', const=1, help='Redirected to GOOGLE MAPS and point out the location')
        parse.add_argument('-all', nargs='?', const=1, help='perfom checks  realted to IPAddress / Domains / Urls / FileScan / hashchecks from All the websites')
        args = parse.parse_args()
        return args

    def start_engine(self):
        start_time = int(datetime.datetime.now().strftime('%M'))
        args = engine.CLI()
        # --------------------
        #   IBM X FORCE PART
        # --------------------
        if args.ip != None and args.ip != 1 and args.ibm == 1:
            # print('Iam in Single IPAddress')
            # print('IP Address : ' + args.ip)
            ipcheck = IBMXForce.IPCheck(API_KEY=Config.properties('IBM', '', 'api_key'),
                                                API_PASSWORD=Config.properties('IBM', '', 'api_pass'),
                                                api=Config.properties('IBM', '', 'ip_api'), mode='Single',
                                                ip=args.ip)
            ip, score, country, category = ipcheck.check_ip()
            print('******* IBM X FORCE IP REPUTATION RESULTS **********')
            print('IP ADDRESS : ' + ip)
            print('REPUTATION SCORE : ' + score)
            print('COUNTRY : ' + country)
            print('CATEGORY : ' + str(category))

        if args.ip == 1 and args.ibm == 1 and args.csv != None and args.csv != 1:
            # print('Iam in Multiple IPAddress')
            # print('IP Address file : ' + args.csv)
            ipcheck = IBMXForce.IPCheck(API_KEY=Config.properties('IBM', '', 'api_key'),
                              API_PASSWORD=Config.properties('IBM', '', 'api_pass'),
                              api=Config.properties('IBM', '', 'ip_api'), mode='Multiple',
                              ipfile=args.csv)
            print('PROCESSING REQUEST .........!')
            print(ipcheck.check_ip())

        if args.domain != None and args.domain != 1 and args.ibm == 1:
            # print('Iam in Single Domain')
            # print('Domain : ' + args.domain)
            domaincheck = IBMXForce.DomainCheck(API_KEY=Config.properties('IBM', '', 'api_key'),
                                      API_PASSWORD=Config.properties('IBM', '', 'api_pass'),
                                      api=Config.properties('IBM', '', 'url_api'), mode='Single',
                                      domain=args.domain)
            print('******** IBM X FORCE DOMAIN REPUTATION RESULTS ********')
            domain, score, country , category = domaincheck.check_domain()
            print('DOMAIN : '+domain)
            print('REPUTATION SCORE : '+score)
            print('COUNTRY : '+country)
            print('CATEGORY : '+str(category))

        if args.domain == 1 and args.ibm == 1 and args.csv != None and args.csv != 1:
            # print('Iam in Multiple Domain')
            # print('Domain file : ' + args.csv)
            domaincheck = IBMXForce.DomainCheck(API_KEY=Config.properties('IBM', '', 'api_key'),
                                      API_PASSWORD=Config.properties('IBM', '', 'api_pass'),
                                      api=Config.properties('IBM', '', 'url_api'), mode='Multiple',
                                      domainfile=args.csv)
            print('PROCESSING REQUEST .........!')
            print(domaincheck.check_domain())

        if args.url != None and args.url != 1 and args.ibm == 1:
            # print('I am in Single url')
            # print('Url : ' + args.url)
            urlcheck = IBMXForce.UrlCheck(API_KEY=Config.properties('IBM', '', 'api_key'),
                                API_PASSWORD=Config.properties('IBM', '', 'api_pass'),
                                api=Config.properties('IBM', '', 'url_api'), mode='Single',
                                url=args.url)
            url, score, country, category = urlcheck.check_url()
            print('********* IBM X FORCE URL REPUTATION RESULTS ************')
            print('URL : '+url)
            print('URL REPUTATION : '+score)
            print('COUNTRY : '+country)
            print('CATEGORY : '+str(category))


        if args.url == 1 and args.ibm == 1 and args.csv != None and args.csv != 1:
            # print('I am in Multiple Url')
            # print('Url file : ' + args.csv)
            urlcheck = IBMXForce.UrlCheck(API_KEY=Config.properties('IBM', '', 'api_key'),
                                          API_PASSWORD=Config.properties('IBM', '', 'api_pass'),
                                          api=Config.properties('IBM', '', 'url_api'), mode='Multiple',
                                          urlfile=args.csv)
            print('PROCESSING REQUEST .................!')
            print(urlcheck.check_url())

        if args.hash != None and args.hash != 1 and args.ibm == 1:
            # print('I am in Single Hash check')
            # print('Hash : ' + args.hash)
            hash_check = IBMXForce.HashCheck(API_KEY=Config.properties('IBM', '', 'api_key'),
                                   API_PASSWORD=Config.properties('IBM', '', 'api_pass'),
                                   api=Config.properties('IBM', '', 'hash_api'), mode='Single',
                                   hash=args.hash)
            hash, family, type, risk = hash_check.check_hash()
            print('******** IBM X FORCE HASH CHECK RESULTS *********')
            print('HASH : '+hash)
            print('BELONGS TO THE FAMILY : '+str(family))
            print('TYPE : '+type)
            print('RISK : '+risk)

        if args.hash == 1 and args.ibm == 1 and args.csv != None and args.csv != 1:
            hash_check = IBMXForce.HashCheck(API_KEY=Config.properties('IBM', '', 'api_key'),
                                   API_PASSWORD=Config.properties('IBM', '', 'api_pass'),
                                   api=Config.properties('IBM', '', 'hash_api'), mode='Multiple',
                                   hashfile=args.csv)
            print('PROCESSING REQUEST .............!')
            print(hash_check.check_hash())

        # -------------------
        #   IPVOID PART
        # -------------------
        if args.ip != None and args.ip != 1 and args.ipvoid == 1:
            # print('I am in IPVoid Single IP Address')
            # print('IP Address : ' + args.ip)
            ipch = IPVoid.IPCheck(mode='Single', http_url=Config.properties('IPVoid', '', 'url'), ip=args.ip)
            ip, score, country, city = ipch.check_ip()
            print('******** IPVOID IP REPUTATION RESULTS ***********')
            print('IP ADDRESS : '+ip)
            print('SCORE : '+score)
            print('COUNTRY : '+country)
            print('CITY : '+city)

        if args.ip == 1 and args.ipvoid == 1 and args.csv != None and args.csv != 1:
            # print('I am in IPVoid Multiple IP Address')
            # print('IP Address file : ' + args.csv)
            ipch = IPVoid.IPCheck(mode='Multiple', http_url=Config.properties('IPVoid', '', 'url'),
                           ipfile=args.csv)
            print('PROCESSING REQUEST ......................!')
            print(ipch.check_ip())

        # ---------------------
        #   VIRUS TOTAL PART
        # ---------------------
        if args.url != None and args.url != 1 and args.virustotal == 1:
            # print('I am in Virus Total Single Url Check')
            # print('Url : ' + args.url)
            uc = VirusTotal.UrlCheck(API_KEY=Config.properties('VirusTotal', '', 'api_key'),
                         api=Config.properties('VirusTotal', '', 'url_api'), mode='Single',
                         url=args.url)
            url, scan_id, score, blacklist_by, permalink = uc.check_url()
            print('********** VIRUS TOTAL URL REPUTATION RESULTS ************')
            print('URL : '+url)
            print('SCAN_ID: '+scan_id)
            print('SCORE : '+score)
            print('VIRUSTOTAL LINK : '+permalink)
            print('BLACKLISTED BY : '+str(blacklist_by))

        if args.url == 1 and args.virustotal == 1 and args.csv != None and args.csv != 1:
            # print('I am in Virus Total Multiple Url Check')
            # print('Url file : ' + args.csv)
            uc = VirusTotal.UrlCheck(API_KEY=Config.properties('VirusTotal', '', 'api_key'),
                                     api=Config.properties('VirusTotal', '', 'url_api'), mode='Multiple',
                                     urlfile=args.csv)
            print('PROCESSING REQUEST ..................!')
            print(uc.check_url())

        if args.hash != None and args.hash != 1 and args.virustotal == 1:
            # print('I am in Virus Total Single hash check')
            # print('Hash : ' + args.hash)
            hc = VirusTotal.HashCheck(API_KEY=Config.properties('VirusTotal', '', 'api_key'), api=Config.properties('VirusTotal', '', 'hash_api'), mode='Single', hash=args.hash)
            scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = hc.check_hash()
            print('********** VIRUS TOTAL HASH CHECK RESULTS **************')
            print('SCAN_ID : '+scan_id)
            print('SCORE : '+score)
            print('MD5 : '+md5)
            print('SHA256 : '+sha256)
            print('SHA1 : '+sha1)
            print('VIRUSTOTAL LINK : '+permalink)
            print('BLACKLISTED BY : '+str(blacklisted_by))


        if args.hash == 1 and args.virustotal == 1 and args.csv != None and args.csv != 1:
            # print('I am in Virus Total Multiple hash check')
            # print('Hash file : ' + args.csv)
            hc = VirusTotal.HashCheck(API_KEY=Config.properties('VirusTotal', '', 'api_key'),
                                      api=Config.properties('VirusTotal', '', 'hash_api'), mode='Multiple',
                                      hashfile=args.csv)
            print('PROCESSING REQUEST .................!')
            print(hc.check_hash())

        if args.filescan != None and args.filescan != 1 and args.virustotal == 1:
            # print('I am in Virus Total Single File Scan')
            # print('FileScan : ' + args.filescan)
            hc = VirusTotal.FileHash(API_KEY=Config.properties('VirusTotal', '', 'api_key'),
                          api_list=[Config.properties('VirusTotal', '', 'filescan_api'),
                                    Config.properties('VirusTotal', '', 'hash_api')], mode='Single',
                          singlefile=args.filescan)
            scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = hc.scan_files()
            print('********** VIRUS TOTAL FILE SCAN RESULTS **************')
            print('SCAN_ID : ' + scan_id)
            print('SCORE : ' + score)
            print('MD5 : ' + md5)
            print('SHA256 : ' + sha256)
            print('SHA1 : ' + sha1)
            print('VIRUSTOTAL LINK : ' + permalink)
            print('BLACKLISTED BY : ' + str(blacklisted_by))

        if args.filescan == 1 and args.virustotal == 1 and args.csv != None and args.csv != 1:
            # print('I am in Virus Total Multiple File Scans')
            # print('File Scan file : ' + args.csv)
            hc = VirusTotal.FileHash(API_KEY=Config.properties('VirusTotal', '', 'api_key'),
                          api_list=[Config.properties('VirusTotal', '', 'filescan_api'),
                                    Config.properties('VirusTotal', '', 'hash_api')], mode='Multiple',
                          multifile=args.csv)
            print('PROCESSING REQUEST .....................!')
            print(hc.scan_files())

        # ---------------------
        #   CISCO TALOS PART
        # ---------------------
        if args.ip != None and args.ip != 1 and args.talos == 1:
            ipcheck = CiscoTalos.IPCheck(driver_path=Config.properties('Talos', '', 'selenium_driver'),
                              http_path=Config.properties('Talos', '', 'url'),
                              mode='Single', ip=args.ip)
            ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = ipcheck.check_ip()
            print('*********** CISOC TALOS IP REPUTATION CHECK RESULTS ***********')
            print('IP ADDRESS : '+ip)
            print('HOSTNAME : '+host)
            print('DOMAIN : '+domain)
            print('COUNTRY : '+ctry)
            print('CITY : '+city)
            print('EMAIL REPUTATION : '+email_rep)
            print('WEB REPUTATION : '+web_rep)
            print('WEIGHT REPUTAITON : '+wght_rep)
            print('SPAM LEVEL : '+str(spam_level))
            print('EMAIL VOLUME : '+str(email_volume))
            print('VOLUME CHANGE : '+str(vol_change))

        if args.ip == 1 and args.talos == 1 and args.csv != None and args.csv != 1:
            ipcheck = CiscoTalos.IPCheck(driver_path=Config.properties('Talos', '', 'selenium_driver'), http_path=Config.properties('Talos', '', 'url'), mode='Multiple', ipfile=args.csv)
            print('PROCESSING REQUEST ...............!')
            print(ipcheck.check_ip())

        if args.domain != None and args.domain != 1 and args.talos == 1:
            domain_check = CiscoTalos.DomainCheck(driver_path=Config.properties('Talos', '', 'selenium_driver'),
                                       http_path=Config.properties('Talos', '', 'url'),
                                       mode='Single', domain=args.domain)
            ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = domain_check.check_domain()
            print('*********** CISOC TALOS DOMAIN REPUTATION CHECK RESULTS ***********')
            print('IP ADDRESS : ' + ip)
            print('HOSTNAME : ' + host)
            print('DOMAIN : ' + domain)
            print('COUNTRY : ' + ctry)
            print('CITY : ' + city)
            print('EMAIL REPUTATION : ' + email_rep)
            print('WEB REPUTATION : ' + web_rep)
            print('WEIGHT REPUTAITON : ' + wght_rep)
            print('SPAM LEVEL : ' + str(spam_level))
            print('EMAIL VOLUME : ' + str(email_volume))
            print('VOLUME CHANGE : ' + str(vol_change))

        if args.domain == 1 and args.talos == 1 and args.csv != None and args.csv != 1:
            # print('I am in Talos Multiple Domain Check')
            # print('Domain file: ' + args.csv)
            domain_check = CiscoTalos.DomainCheck(driver_path=Config.properties('Talos', '', 'selenium_driver'),
                                                  http_path=Config.properties('Talos', '', 'url'),
                                                  mode='Multiple',
                                                  domainfile=args.csv)
            print('PROCESSING REQUEST ...............!')
            print(domain_check.check_domain())

        if args.url != None and args.url != 1 and args.talos == 1:
            # print('I am in Talos Single Url Check')
            # print('Url : ' + args.url)
            url_check = CiscoTalos.UrlCheck(driver_path=Config.properties('Talos', '', 'selenium_driver'), http_path=Config.properties('Talos', '', 'url'), mode='Single', url=args.url)
            ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = url_check.check_url()
            print('*********** CISOC TALOS URL REPUTATION CHECK RESULTS ***********')
            print('IP ADDRESS : ' + ip)
            print('HOSTNAME : ' + host)
            print('DOMAIN : ' + domain)
            print('COUNTRY : ' + ctry)
            print('CITY : ' + city)
            print('EMAIL REPUTATION : ' + email_rep)
            print('WEB REPUTATION : ' + web_rep)
            print('WEIGHT REPUTAITON : ' + wght_rep)
            print('SPAM LEVEL : ' + str(spam_level))
            print('EMAIL VOLUME : ' + str(email_volume))
            print('VOLUME CHANGE : ' + str(vol_change))

        if args.url == 1 and args.talos == 1 and args.csv != None and args.csv != 1:
            # print('I am in Talos Multiple Url Check')
            # print('Url file : ' + args.csv)
            url_check = CiscoTalos.UrlCheck(driver_path=Config.properties('Talos', '', 'selenium_driver'), http_path=Config.properties('Talos', '', 'url'), mode='Multiple', urlfile=args.csv)
            print('PROCESSING REQUEST .................!')
            print(url_check.check_url())

        # ----------------------
        #   IP LOCATION PART
        # ----------------------
        if args.ip != None and args.ip != 1 and args.location == 1:
            lc = IPLocation.LocationCheck(http_url=Config.properties('IPLocation', '', 'url'), mode='Single',
                               ip=args.ip)
            ip, country, city, region, isp, lat, lon = lc.check_location()
            print('*********** IP LOCATION RESULTS ***********')
            print('IP ADDRESS : '+ip)
            print('COUNTRY : '+country)
            print('CITY : '+city)
            print('REGION : '+region)
            print('ISP : '+isp)
            print('LATITUDE : '+str(lat))
            print('LONGITUDE : '+str(lon))

        if args.ip == 1 and args.location == 1 and args.csv != None and args.csv != 1:
            lc = IPLocation.LocationCheck(http_url=Config.properties('IPLocation', '', 'url'), mode='Multiple',
                               ipfile=args.csv)
            print('PROCESSING REQUEST ...............!')
            print(lc.check_location())

        if args.ip not in [None, 1] and args.location == 1 and args.view == 1:
            lc = IPLocation.LocationCheck(http_url=Config.properties('IPLocation', '', 'url'), mode='Single',
                                          ip=args.ip)
            lc.check_location(driver_path=Config.properties('Talos', '', 'selenium_driver'), http_path=Config.properties('IPLocation', '', 'map'), view_time = 30)

        if args.ip not in [None, 1] and args.all == 1:
            ip_check_all = All_Sites.IPCheck(IBM_API_KEY=Config.properties('IBM', '', 'api_key'), IBM_API_PASSWORD=Config.properties('IBM', '', 'api_pass'), ibm_api=Config.properties('IBM', '', 'ip_api'), ipvoid_path=Config.properties('IPVoid', '', 'url'), talos_path=Config.properties('Talos', '', 'url'), iplocation_path=Config.properties('IPLocation', '', 'url'), ip=args.ip)
            ibm_list, ipvoid_list, talos_list, iploc_list = ip_check_all.check_ip()
            print('********* IBM X FORCE *************')
            print('   IP ADDRESS : '+str(ibm_list[0]))
            print('   REPUATION SCORE : '+ibm_list[1])
            print('   COUNTRY : '+ibm_list[2])
            print('   CATEGORY : '+str(ibm_list[3]))
            print('*********** IPVOID *****************')
            print('   IP ADDRESS : ' + ipvoid_list[0])
            print('   REPUATION SCORE : ' + ipvoid_list[1])
            print('   COUNTRY : ' + ipvoid_list[2])
            print('   CITY : ' + ipvoid_list[3])
            print('********** CISCO TALOS *************')
            print('   IPADDRESS : '+talos_list[0])
            print('   HOST NAME : '+talos_list[1])
            print('   DOMAIN : '+talos_list[2])
            print('   COUNTRY : '+talos_list[3])
            print('   CITY : '+talos_list[4])
            print('   EMAIL REPUTATION : '+talos_list[5])
            print('   WEB REPUTATION : '+talos_list[6])
            print('   WEIGHT REPUTATION : '+talos_list[7])
            print('   SPAM LEVEL : '+str(talos_list[8]))
            print('   EMAIL VOLUME : '+str(talos_list[9]))
            print('   VOLUME CHANGE : '+str(talos_list[10]))
            print('*********** IPLOCATION **************')
            print('   IPADDRESS : '+iploc_list[0])
            print('   COUNTRY : '+iploc_list[1])
            print('   CITY : '+iploc_list[2])
            print('   REGION : '+iploc_list[3])
            print('   ISP : '+iploc_list[4])
            print('   LATITUDE : '+iploc_list[5])
            print('   LONGITUDE : '+iploc_list[6])

        if args.domain not in [None, 1] and args.all == 1:
            print('I am in domain check all')
            dom_check = All_Sites.DomainCheck(IBM_API_KEY=Config.properties('IBM', '', 'api_key'), IBM_API_PASSWORD=Config.properties('IBM', '', 'api_pass'), ibm_api=Config.properties('IBM', '', 'url_api'), talos_path=Config.properties('Talos', '', 'url'), domain=args.domain)
            ibm_list, talos_list = dom_check.check_domain()
            print('********* IBM X FORCE *************')
            print('   DOMAIN : ' + str(ibm_list[0]))
            print('   REPUATION SCORE : ' + ibm_list[1])
            print('   COUNTRY : ' + ibm_list[2])
            print('   CATEGORY : ' + str(ibm_list[3]))
            print('********** CISCO TALOS *************')
            print('   IPADDRESS : ' + talos_list[0])
            print('   HOST NAME : ' + talos_list[1])
            print('   DOMAIN : ' + talos_list[2])
            print('   COUNTRY : ' + talos_list[3])
            print('   CITY : ' + talos_list[4])
            print('   EMAIL REPUTATION : ' + talos_list[5])
            print('   WEB REPUTATION : ' + talos_list[6])
            print('   WEIGHT REPUTATION : ' + talos_list[7])
            print('   SPAM LEVEL : ' + str(talos_list[8]))
            print('   EMAIL VOLUME : ' + str(talos_list[9]))
            print('   VOLUME CHANGE : ' + str(talos_list[10]))

        if args.url not in [None, 1] and args.all == 1:
            print('I am in url check all')
            url_check = All_Sites.UrlCheck(IBM_API_KEY=Config.properties('IBM', '', 'api_key'), IBM_API_PASSWORD=Config.properties('IBM', '', 'api_pass'), VIRUSTOTAL_API=Config.properties('VirusTotal', '', 'api_key'), ibm_api=Config.properties('IBM', '', 'url_api'), virustotal_api=Config.properties('VirusTotal', '', 'url_api'), talos_path=Config.properties('Talos', '', 'url'), url=args.url)
            ibm_list, virus_total_list, talos_list = url_check.check_url()
            print('********* IBM X FORCE *************')
            print('   URL : ' + str(ibm_list[0]))
            print('   REPUATION SCORE : ' + ibm_list[1])
            print('   COUNTRY : ' + ibm_list[2])
            print('   CATEGORY : ' + str(ibm_list[3]))
            print('********** VIRUS TOTAL ************')
            print('URL : ' + virus_total_list[0])
            print('SCAN_ID: ' + virus_total_list[1])
            print('SCORE : ' + virus_total_list[2])
            print('VIRUSTOTAL LINK : ' + virus_total_list[4])
            print('BLACKLISTED BY : ' + str(virus_total_list[3]))
            print('********** CISCO TALOS *************')
            print('   IPADDRESS : ' + talos_list[0])
            print('   HOST NAME : ' + talos_list[1])
            print('   DOMAIN : ' + talos_list[2])
            print('   COUNTRY : ' + talos_list[3])
            print('   CITY : ' + talos_list[4])
            print('   EMAIL REPUTATION : ' + talos_list[5])
            print('   WEB REPUTATION : ' + talos_list[6])
            print('   WEIGHT REPUTATION : ' + talos_list[7])
            print('   SPAM LEVEL : ' + str(talos_list[8]))
            print('   EMAIL VOLUME : ' + str(talos_list[9]))
            print('   VOLUME CHANGE : ' + str(talos_list[10]))

        if args.hash not in [None, 1] and args.all == 1:
            print('I am in hash check all')
            hash_chk = All_Sites.HashCheck(IBM_API_KEY=Config.properties('IBM', '', 'api_key'), IBM_API_PASSWORD=Config.properties('IBM', '', 'api_pass'), VIRUSTOTAL_API=Config.properties('VirusTotal', '', 'api_key'), ibm_api=Config.properties('IBM', '', 'hash_api'), virustotal_api=Config.properties('VirusTotal', '', 'hash_api'), hash=args.hash)
            ibm_list, virus_total_list = hash_chk.check_hash()
            print('********* IBM X FORCE *************')
            print('   HASH : ' + str(ibm_list[0]))
            print('   FAMILY : ' + str(ibm_list[1]))
            print('   TYPE : ' + ibm_list[2])
            print('   RISK : ' + str(ibm_list[3]))
            print('********** VIRUS TOTAL ************')
            print('   SCAN_ID: ' + virus_total_list[0])
            print('   SCORE : ' + virus_total_list[1])
            print('   MD5 : ' + virus_total_list[2])
            print('   SHA256 : ' + virus_total_list[3])
            print('   SHA1 : ' + virus_total_list[4])
            print('   VIRUSTOTAL LINK : ' + virus_total_list[5])
            print('   BLACKLISTED BY : ' + str(virus_total_list[6]))

        if args.filescan not in [None, 1] and args.all == 1:
            print('I am in filescan all')
            vfs = All_Sites.FileScan(VIRUSTOTAL_API_KEY=Config.properties('VirusTotal', '', 'api_key'), virustotal_api=[Config.properties('VirusTotal', '', 'filescan_api'), Config.properties('VirusTotal', '', 'hash_api')], filescan=args.filescan)
            virus_total_list = vfs.check_filescan()
            print('********** VIRUS TOTAL FILE SCAN RESULTS **************')
            print('SCAN_ID : ' + virus_total_list[0])
            print('SCORE : ' + virus_total_list[1])
            print('MD5 : ' + virus_total_list[2])
            print('SHA256 : ' + virus_total_list[3])
            print('SHA1 : ' + virus_total_list[4])
            print('VIRUSTOTAL LINK : ' + virus_total_list[5])
            print('BLACKLISTED BY : ' + str(virus_total_list[6]))

        end_time = int(datetime.datetime.now().strftime('%M'))
        print('COMPLETED WITHIN : '+str(end_time-start_time)+' MINUTES')

if __name__ == '__main__':
    engine = UREngine()
    engine.start_engine()