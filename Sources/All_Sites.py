import base64, requests, os, time
from bs4 import BeautifulSoup as bs
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from threading import Thread
from Config import Config
# -----------------------------------
#   PARENT CLASS FOR REPUATION CHECK
# -----------------------------------
class Reputation:

    def __init__(self, IBM_API_KEY=None, IBM_API_PASSWORD=None, VIRUSTOTAL_API_KEY=None):
        if IBM_API_KEY != None:
            self.IBM_API_KEY = IBM_API_KEY
        if IBM_API_PASSWORD != None:
            self.IBM_API_PASSWORD = IBM_API_PASSWORD
        if VIRUSTOTAL_API_KEY != None:
            self.VIRUSTOTAL_API_KEY = VIRUSTOTAL_API_KEY

    # --------------------------------------------------
    #   ENCODE IBM API KEY AND API PASSWORD TO BASE 64
    # --------------------------------------------------
    def encode_authorization(self):
        pass_data = self.IBM_API_KEY+':'+self.IBM_API_PASSWORD
        data = base64.b64encode(pass_data.encode())
        return str(data.decode('utf-8'))

    # ----------------------------
    #   HEADERS FOR IBM API CALL
    # ----------------------------
    def headers(self):
        header = {"Authorization": "Basic "+self.encode_authorization(), "Content-Type":"application/json"}
        return header

    # ------------------------------
    #   ERROR CODES DESCRIPTION
    # ------------------------------
    def error_status(self, error_code):
        error_dict = {400: 'INVALID API KEY FORMAT', 401: 'UNAUTHORIZED', 402: 'YOUR MONTHLY QUOTA EXCEEDED',
                      403: 'ACCESS DENIED', 404: 'API KEY NOT FOUND', 406: 'NO ACCEPTABLE TYPE SPECIFIED',
                      429: 'RATE LIMIT', 500: 'INTERNAL ERROR'}
        try:
            return error_dict[error_code]
        except:
            return 'ERROR IN MAKING API CALL TO IBM X FORCE. ERROR CODE : '+str(error_code)

    # ------------------------
    #   SELENIUM DRIVER
    # ------------------------
    def selenium_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument('--log-level=3')
        driver = webdriver.Chrome(executable_path=Config.properties('Talos', '', 'selenium_driver'),
                                  chrome_options=chrome_options, service_log_path='NUL')
        return driver
    def loc_driver(self, driver,lat, lon):
        driver.get('https://www.google.co.in/maps/place/'+lat+', '+lon)
        time.sleep(30)
        driver.quit()
    # ----------------------------
    #   CHECK FOR VALID IP
    # ----------------------------
    def is_valid_ip(self, ip_add):
        ip = ip_add.strip()
        try:
            if (int(str(ip).split('.')[0]) == 10) or (int(str(ip).split('.')[0]) == 172 and int(str(ip).split('.')[1]) in range(16, 31)) or (int(str(ip).split('.')[0]) == 192 and int(str(ip).split('.')[1]) == 168):
                return False
            else:
                return True
        except:
            print('INVALID IPADDRESS')
            return 'Not IP'

    # --------------------------
    #   CHECK VALID DOMAIN
    # --------------------------
    def is_valid_domain(self, domain):
        dom = domain.strip()
        li = ['com', 'in', 'net', 'gr', 'co', 'app', 'online', 'space', 'store', 'tech', 'org', 'club', 'design',
              'shop', 'iste', 'io', 'me', 'us', 'ca', 'ac', 'academy', 'accountant', 'actor', 'adult', 'ae.org', 'ae',
              'af', 'africa', 'ag', 'agency', 'ai', 'am', 'apartments', 'com.ar', 'archi', 'art', 'as', 'asia',
              'associates', 'at', 'attorney', 'com.au', 'id.au', 'net.au', 'au', 'org.au', 'auction']
        try:
            if dom.split('.')[-1] in li:
                return True
            elif dom.split('.')[-2] in li:
                return True
            else:
                return False
        except:
            return False
    # -----------------------------
    #   CISCO TALOS WEBSCRAPPING
    # -----------------------------
    def location_check(self, soap, ctry, city):
        for div in soap.findAll('div', {"id": "location-data-wrapper"}):
            if len(div.findAll('table')) != 0:
                for table in div.findAll('table'):
                    for row in table.findAll('td'):
                        if row.text != '':
                            try:
                                city = row.text.split(',')[0]
                                ctry = row.text.split(',')[1]
                            except:
                                ctry = row.text
                                city = 'No Info'
                        else:
                            ctry, city = 'No Info', 'No Info'
            else:
                ctry = city = 'No Info'
        return ctry, city

    def reputation_check(self, soap, email_rep, web_rep, wght_rep):
        span_lst = []
        for div in soap.findAll('div', {"id": "email-data-wrapper"}):
            for table in div.findAll('td'):
                for span in table.findAll('span'):
                    span_lst.append(span.text)
        if len(span_lst) != 0:
            if span_lst[1].__contains__('Email Reputation'):
                email_rep = span_lst[2]
            else:
                email_rep = 'No Info'

            if span_lst[3].__contains__('Web Reputation'):
                web_rep = span_lst[5]
            elif span_lst[1].__contains__('Web Reputation'):
                web_rep = span_lst[2]
            else:
                web_rep = 'No Info'

            if span_lst[6].__contains__('Weighted Reputation'):
                wght_rep = span_lst[8]
            elif span_lst[3].__contains__('Weighted Reputation'):
                wght_rep = span_lst[5]
            elif span_lst[1].__contains__('Weighted Reputation'):
                wght_rep = span_lst[2]
            else:
                wght_rep = 'No Info'

            return email_rep, web_rep, wght_rep
        else:
            email_rep = web_rep = wght_rep = 'No Info'
            return email_rep, web_rep, wght_rep

    def basic_details(self, soap, ip, host, domain):
        alist = []
        for div in soap.findAll('div', {"id": "owner-data-wrapper"}):
            for table in div.findAll('td'):
                for a in table.findAll('a'):
                    alist.append(a.text)
        if len(alist) == 5:
            ip = alist[0]
            host = alist[2]
            domain = alist[3]
        elif len(alist) == 4:
            ip = alist[0]
            host = alist[1]
            domain = alist[2]
        elif len(alist) == 3:
            if self.is_valid_ip(alist[0]) != 'Not IP' and self.is_valid_domain(alist[2]):
                ip = alist[0]
                host = alist[1]
                domain = alist[2]
            elif self.is_valid_domain(alist[0]):
                ip = 'No Info'
                domain = alist[0]
                host = alist[1]
            elif self.is_valid_domain(alist[1]):
                ip = 'No Info'
                host = alist[0]
                domain = alist[1]
        elif len(alist) == 2:
            if self.is_valid_ip(alist[0]) != 'Not IP':
                ip = alist[0]
                if self.is_valid_domain(alist[1]):
                    domain = alist[1]
                else:
                    host = alist[1]
            elif self.is_valid_domain(alist[0]):
                ip = 'No Info'
                host = 'No Info'
                domain = alist[0]
            elif self.is_valid_domain(alist[1]):
                ip = 'No Info'
                host = 'No Info'
                domain = alist[1]
            elif self.is_valid_domain(alist[0]) == False:
                ip = 'No Info'
                domain = 'No Info'
                host = alist[0]
            elif self.is_valid_domain(alist[1]) == False:
                ip = 'No Info'
                domain = 'No Info'
                host = alist[1]
        elif len(alist) == 1:
            if self.is_valid_ip(alist[0]) != 'Not IP':
                ip = alist[0]
                host = 'No Info'
                domain = 'No Info'
            elif self.is_valid_domain(alist[0]):
                ip = 'No Info'
                domain = alist[0]
                host = 'No Info'
            else:
                ip = 'No Info'
                domain = 'No Info'
                host = alist[0]
        elif len(alist) == 0:
            ip, host, domain = 'No Info', 'No Info', 'No Info'
        return ip, host, domain

    def score(self, soap, spam_level, email_vol, vol_change):
        score_lst = []
        for div in soap.findAll('div', {"id": "email-data-wrapper"}):
            for table in div.findAll('td', {"class": "text-center"}):
                score_lst.append(table.text)
        if len(score_lst) != 0:
            try:
                if isinstance(int(score_lst[0].split('.')[0]), int):
                    spam_level['Last Day'] = 'No Info'
                    spam_level['Last Month'] = 'No Info'
                    email_vol['Last Day'] = score_lst[0]
                    email_vol['Last Month'] = score_lst[1]
                    vol_change['Last Day'] = score_lst[2]
                    try:
                        vol_change['Last Day'] = score_lst[3]
                    except IndexError:
                        vol_change['Last Month'] = 'No Info'
                else:
                    spam_level['Last Day'] = score_lst[0]
                    spam_level['Last Month'] = score_lst[1]
                    email_vol['Last Day'] = score_lst[2]
                    email_vol['Last Month'] = score_lst[3]
                    vol_change['Last Day'] = score_lst[4]
                    try:
                        vol_change['Last Day'] = score_lst[5]
                    except IndexError:
                        vol_change['Last Month'] = 'No Info'
            except:
                spam_level['Last Day'] = score_lst[0]
                spam_level['Last Month'] = score_lst[1]
                email_vol['Last Day'] = score_lst[2]
                email_vol['Last Month'] = score_lst[3]
                vol_change['Last Day'] = score_lst[4]
                try:
                    vol_change['Last Day'] = score_lst[5]
                except IndexError:
                    vol_change['Last Month'] = 'No Info'
        else:
            spam_level['Last Day'], email_vol['Last Day'], vol_change['Last Day'], spam_level['Last Month'], email_vol['Last Month'], vol_change['Last Month']= 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info'
        return spam_level, email_vol, vol_change

# --------------------------------------------------------------------------------------------------
#   IP REPUATION CHECK INHERITED FROM REPUTATION CLASS (IBMXFORCE, IPVOID, CISCO TALOS, IPLOCATION)
# ---------------------------------------------------------------------------------------------------
class IPCheck(Reputation):

    def __init__(self, IBM_API_KEY, IBM_API_PASSWORD, ibm_api, ipvoid_path, talos_path, iplocation_path, ip):
        Reputation.__init__(self, IBM_API_KEY=IBM_API_KEY, IBM_API_PASSWORD=IBM_API_PASSWORD)
        self.ibm_api = ibm_api
        self.ipvoid_path = ipvoid_path
        self.talos_path = talos_path
        self.iplocation_path = iplocation_path
        self.ip = ip

    def ibmxforce(self, ip_add, ibm_list):
        if self.is_valid_ip(ip_add):
            ip, score, country, category = '', '', '', []
            try:
                response = requests.get(self.ibm_api+ip_add, headers=self.headers())
                if response.status_code == 200:
                    json_response = response.json()
                    try:
                        ip = ip_add
                    except:
                        ip = 'No Info'
                    try:
                        score = str(json_response['score']) + ' Out of 10'
                    except:
                        score = 'No Info'
                    try:
                        country = json_response['history'][0]['geo']['country']
                    except:
                        country = 'No Info'
                    try:
                        category_data = json_response['categoryDescriptions']
                        if len(category_data) != 0:
                            cat_list = ['Spam', 'Scanning IPs', 'Dynamic IPs', 'Anonymous']
                            for cat in cat_list:
                                try:
                                    json_response['categoryDescriptions'][cat]
                                    category.append(cat)
                                except:
                                    pass
                        else:
                            category.append('Unsuspicious')
                    except:
                        category.append('No Info')
                else:
                    print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                    ip, score, country, category = ip, 'No Info', 'No Info', 'No Info'
            except requests.exceptions.ConnectTimeout:
                print('REQUEST TIMED OUT')
            except requests.exceptions.ConnectionError:
                print('UNABLE TO CONNECTION TO IBMXFORCE CHECK YOUR INTERNET CONNECTION')
            li = [ip, score, country, category]
            for i in li:
                ibm_list.append(i)

    def ipvoid(self, ip, ipvoid_list):
        if self.is_valid_ip(ip):
            try:
                formdata = {'ip': ip}
                response = requests.post(self.ipvoid_path, formdata)
                if response.status_code == 201 or response.status_code == 200:
                    soap = bs(response.content, 'html.parser')
                    table = soap.find('table')
                    tds, ip = score = country = city = [], ''
                    for row in table.findAll('tr'):
                        for col in row.findAll('td'):
                            tds.append(col.text.strip())
                    try:
                        ip = tds[7].replace('Find Sites | IP Whois', '')
                    except:
                        ip = 'No Info'
                    try:
                        score = tds[5]
                    except:
                        score = 'No Info'
                    try:
                        country = tds[19]
                    except:
                        country = 'No Info'
                    try:
                        city = tds[23]
                    except:
                        city = 'No Info'
                    for i in [ip, score, country, city]:
                        ipvoid_list.append(i)
                else:
                    print('ERROR IN IPVOID CONNECTION : ' + self.error_status(response.status_code))
                    for i in ['No Info', 'No Info', 'No Info', 'No Info']:
                        ipvoid_list.append(i)

            except requests.exceptions.ConnectTimeout:
                print('UNABLE TO PROCESS REQUEST, CONNECTION TIME OUT')
            except requests.exceptions.ConnectionError:
                print('UNABLE TO CONNECT IPVOID')

        else:
            ip = score = country = city = 'No Info'
            for i in [ip, score, country, city]:
                ipvoid_list.append(i)

    def talos(self, ip_add, driver, talos_list):
        driver.get(self.talos_path + ip_add)
        response = driver.page_source
        driver.quit()
        soap = bs(response, 'html.parser')
        ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
        email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
        ip, host, domain = self.basic_details(soap, ip, host, domain)
        spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
        for i in [ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change]:
            talos_list.append(i)

    def iplocation(self, ip_add, iploc_list):
        if self.is_valid_ip(ip_add):
            try:
                formdata = {'query': ip_add}
                response = requests.get(self.iplocation_path, params=formdata)
                if response.status_code == 200 or response.status_code == 201:
                    soap = bs(response.content, 'html.parser')
                    table = soap.find('table')
                    tds = []
                    for row in table.findAll('td'):
                        tds.append(row.text.strip())
                    ip = country = city = region = isp = lat = lon = ''
                    try:
                        ip = tds[0]
                    except:
                        ip = 'No Info'
                    try:
                        country = tds[1]
                    except:
                        country = 'No Info'
                    try:
                        region = tds[2]
                    except:
                        region = 'No Info'
                    try:
                        city = tds[3]
                    except:
                        city = 'No Info'
                    try:
                        isp = tds[4]
                    except:
                        isp = 'No Info'
                    try:
                        lat = tds[6]
                    except:
                        lat = 'No Info'
                    try:
                        lon = tds[7]
                    except:
                        lon = 'No Info'

                    for i in [ip, country, city, region, isp, lat, lon]:
                        iploc_list.append(i)
                else:
                    print('ERROR IN HTTP CONNECTIONS : ' + self.error_status(response.status_code))
                    for i in [ip_add, 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info']:
                        iploc_list.append(i)

            except requests.exceptions.ConnectionError:
                print('UNBALE TO CONNECT TO IPLOCATION WEBSITE')

    def check_ip(self):
        ibm_list, ipvoid_list, talos_list, iploc_list = [], [], [], []
        t1 = Thread(target=self.ibmxforce, args=(self.ip, ibm_list))
        t2 = Thread(target=self.ipvoid, args=(self.ip, ipvoid_list))
        t3 = Thread(target=self.talos, args=(self.ip, self.selenium_driver(), talos_list))
        t4 = Thread(target=self.iplocation, args=(self.ip, iploc_list))
        li = [t1, t2, t3, t4]
        for thread in li:
            thread.start()
        for thread in li:
            thread.join()
        return ibm_list, ipvoid_list, talos_list, iploc_list

# -------------------------------------------------------------------------------------
#   DOMAIN REPUTATION CHECK INHERITED FROM REPUTATION CLASS (IBMXFORCE, CISCO TALOS)
# -------------------------------------------------------------------------------------
class DomainCheck(Reputation):

    def __init__(self, IBM_API_KEY, IBM_API_PASSWORD, ibm_api, talos_path, domain):
        Reputation.__init__(self, IBM_API_KEY=IBM_API_KEY, IBM_API_PASSWORD=IBM_API_PASSWORD)
        self.ibm_api = ibm_api
        self.talos_path = talos_path
        self.domain = domain

    def ibmxforce(self, domain_name, ibm_list):
        try:
            domain = score = country, category = '', []
            response = requests.get(self.ibm_api + domain_name, headers=self.headers())
            if response.status_code == 200:
                json_response = response.json()
                try:
                    domain = json_response['result']['url']
                except:
                    domain = 'No Info'
                try:
                    score = str(json_response['result']['score']) + ' Out of 10'
                except:
                    score = 'No Info'
                try:
                    country = json_response['history'][0]['geo']['country']
                except:
                    country = 'No Info'
                try:
                    category_data = json_response['result']['cats']
                    if len(category_data) != 0:
                        category.append(list(category_data.keys()))
                    else:
                        category.append('Unsuspicious')
                except:
                    category.append('No Info')
            else:
                print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                domain, score, country, category = self.domain, 'No Info', 'No Info', 'No Info'
            for i in [domain, score, country, category]:
                ibm_list.append(i)
        except requests.exceptions.ConnectionError:
            print('CHECK YOUR INTERNET CONNECTION')

    def talos(self, driver, domain_name, talos_list):
        driver.get(self.talos_path + domain_name)
        response = driver.page_source
        driver.quit()
        soap = bs(response, 'html.parser')
        ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
        email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
        ip, host, domain = self.basic_details(soap, ip, host, domain)
        spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
        for i in [ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change]:
            talos_list.append(i)

    def check_domain(self):
        ibm_list, talos_list = [], []
        t1 = Thread(target=self.ibmxforce, args=(self.domain, ibm_list))
        t2 = Thread(target=self.talos, args=(self.selenium_driver(), self.domain, talos_list))
        for thread in [t1, t2]:
            thread.start()
        for thread in [t1, t2]:
            thread.join()
        return ibm_list, talos_list

# ---------------------------------------------------------------------------------
#   URL CHECK INHERITED FROM REPUTATION CLASS (IBMXFORCE, VIRUSTOTAL, CISCOTALOS)
# ---------------------------------------------------------------------------------
class UrlCheck(Reputation):

    def __init__(self, IBM_API_KEY, IBM_API_PASSWORD, VIRUSTOTAL_API, ibm_api, virustotal_api, talos_path, url):
        Reputation.__init__(self, IBM_API_KEY, IBM_API_PASSWORD, VIRUSTOTAL_API)
        self.ibm_api = ibm_api
        self.virustotal_api = virustotal_api
        self.talos_path = talos_path
        self.url = url

    def ibmxforce(self, url_name, ibm_list):
        try:
            url = score = country, category = '', []
            response = requests.get(self.ibm_api + url_name, headers=self.headers())
            if response.status_code == 200:
                json_response = response.json()
                try:
                    url = json_response['result']['url']
                except:
                    url = 'No Info'
                try:
                    score = str(json_response['result']['score']) + ' Out of 10'
                except:
                    score = 'No Info'
                try:
                    country = json_response['history'][0]['geo']['country']
                except:
                    country = 'No Info'
                try:
                    category_data = json_response['result']['cats']
                    if len(category_data) != 0:
                        category.append(list(category_data.keys()))
                    else:
                        category.append('Unsuspicious')
                except:
                    category.append('No Info')
            else:
                print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                url, score, country, category = self.url, 'No Info', 'No Info', 'No Info'
            for i in [url, score, country, category]:
                ibm_list.append(i)
        except requests.exceptions.ConnectionError:
            print('CHECK YOUR INTERNET CONNECTION')

    def virustotal(self, url_name, virus_total_list):
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        url, scan_id, score, blacklist_by, permalink = '', '', '', [], ''
        params = {'apikey': self.VIRUSTOTAL_API_KEY, 'resource': url_name}
        try:
            response = requests.post(self.virustotal_api, params=params, headers=headers)
            if response.status_code != 204:
                try:
                    json_response = response.json()
                    while (True):
                        if json_response['response_code'] != -2:
                            try:
                                url = self.url
                            except:
                                url = 'No Info'
                            try:
                                score = str(json_response['positives']) + '/' + str(json_response['total'])
                            except:
                                score = 'No Info'
                            try:
                                scan_id = json_response['scan_id']
                            except:
                                scan_id = 'No Info'
                            try:
                                for data in json_response['scans']:
                                    if json_response['scans'][data]['detected'] == True:
                                        blacklist_by.append(data)
                            except:
                                blacklist_by = []
                            try:
                                permalink = json_response['permalink']
                            except:
                                permalink = 'No Info'
                            break
                except:
                    print('NOT ABLE TO PARSE THE JSON DATA')
                    url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
            elif response.status_code == 204:
                print('API LIMIT EXCEEDED')
                url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
            else:
                print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : ' + self.error_status(
                    response.status_code))
                url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
            for i in [url, scan_id, score, blacklist_by, permalink]:
                virus_total_list.append(i)

        except requests.exceptions.ConnectionError:
            print('NOT ABLE TO CONNECT TO VIRUSTOTAL')

    def talos(self, driver, url_name, talos_list):
        driver.get(self.talos_path + url_name)
        response = driver.page_source
        driver.quit()
        soap = bs(response, 'html.parser')
        ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
        email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
        ip, host, domain = self.basic_details(soap, ip, host, domain)
        spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
        for i in [ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change]:
            talos_list.append(i)

    def check_url(self):
        ibm_list, virus_total_list, talos_list = [], [], []
        t1 = Thread(target=self.ibmxforce, args=(self.url, ibm_list))
        t2 = Thread(target=self.virustotal, args=(self.url, virus_total_list))
        t3 = Thread(target=self.talos, args=(self.selenium_driver(), self.url, talos_list))
        for thread in [t1, t2, t3]:
            thread.start()
        for thread in [t1, t2, t3]:
            thread.join()
        return ibm_list, virus_total_list, talos_list
# ---------------------------------------------------------------------
#   HASH CHECK INHERITED FROM REPUTATION CLASS (IBMXFORCE, VIRUSTOTAL)
# ---------------------------------------------------------------------
class HashCheck(Reputation):

    def __init__(self, IBM_API_KEY, IBM_API_PASSWORD, VIRUSTOTAL_API, ibm_api, virustotal_api, hash):
        Reputation.__init__(self, IBM_API_KEY, IBM_API_PASSWORD, VIRUSTOTAL_API)
        self.ibm_api = ibm_api
        self.virustotal_api = virustotal_api
        self.hash = hash

    def ibmxforce(self, hash_name, ibm_list):
        try:
            family, type, risk = [], '', ''
            response = requests.get(self.ibm_api + hash_name, headers=self.headers())
            if response.status_code == 200:
                json_response = response.json()
                try:
                    family.append(json_response['malware']['origins']['external']['family'])
                except:
                    family.append('No Info')
                try:
                    type = json_response['malware']['type']
                except:
                    type = 'No Info'
                try:
                    risk = json_response['malware']['risk']
                except:
                    risk = 'No Info'
            else:
                print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                family, type = risk = ['No Info'], 'No Info'

            for i in [hash_name, family, type, risk]:
                ibm_list.append(i)

        except requests.exceptions.ConnectionError:
            print('CHECK YOUR INTERNET CONNECTION')

    def virustotal(self, hash_name, virus_total_list):
        scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = '', '', '', '', '', '', []
        params = {'apikey': self.VIRUSTOTAL_API_KEY, 'resource': hash_name}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        try:
            response = requests.get(self.virustotal_api, params=params, headers=headers)
            if response.status_code != 204:
                json_response = response.json()

                try:
                    scan_id = json_response['scan_id']
                except:
                    scan_id = 'No Info'
                try:
                    score = str(json_response['positives']) + '/' + str(json_response['total'])
                except:
                    score = 'No Info'
                try:
                    md5 = json_response['md5']
                except:
                    md5 = 'No Info'
                try:
                    sha256 = json_response['sha256']
                except:
                    sha256 = 'No Info'
                try:
                    sha1 = json_response['sha1']
                except:
                    sha1 = 'No Info'
                try:
                    permalink = json_response['permalink']
                except:
                    permalink = 'No Info'
                try:
                    while (True):
                        if json_response['response_code'] != -2:
                            for data in json_response['scans']:
                                if json_response['scans'][data]['detected'] == True:
                                    blacklisted_by.append(data)
                            break
                except:
                    blacklisted_by = []

            elif response.status_code == 204:
                print('API LIMIT EXCEEDED')
                scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
            else:
                print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : ' + self.error_status(
                    response.status_code))
                scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
            for i in [scan_id, score, md5, sha256, sha1, permalink, blacklisted_by]:
                virus_total_list.append(i)

        except requests.exceptions.ConnectionError:
            print('NOT ABLE TO CONNECT TO VIRUSTOTAL')
        except requests.exceptions.ConnectTimeout:
            print('CONNECITON TIMED OUT')

    def check_hash(self):
        ibm_list, virus_total_list = [], []
        t1 = Thread(target=self.ibmxforce, args=(self.hash, ibm_list))
        t2 = Thread(target=self.virustotal, args=(self.hash, virus_total_list))
        for thread in [t1, t2]:
            thread.start()
        for thread in [t1, t2]:
            thread.join()
        return ibm_list, virus_total_list

# --------------------------------------------------------
#   FILE SCAN INHERTIED FROM REPUAITON CLASS (VIRUSTOTAL)
# --------------------------------------------------------
class FileScan(Reputation):

    def __init__(self, VIRUSTOTAL_API_KEY, virustotal_api, filescan):
        Reputation.__init__(self, VIRUSTOTAL_API_KEY=VIRUSTOTAL_API_KEY)
        self.virustotal_api = virustotal_api
        self.filescan = filescan

    def virustotal(self, filescan, virus_total_list):
        headers = {"Accept-Encoding": "gzip, deflate", }
        scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = '', '', '', '', '', '', []
        files = {'file': (filescan, open(filescan, 'rb'))}
        params = {'apikey': self.VIRUSTOTAL_API_KEY}
        try:
            response = requests.post(self.virustotal_api[0], files=files, params=params)
            if response.status_code != 204:
                json_response = response.json()
                resource = json_response['resource']
                params = {'apikey': self.VIRUSTOTAL_API_KEY, 'resource': resource}
                response = requests.get(self.virustotal_api[1], params=params, headers=headers)
                json_response = response.json()
                try:
                    scan_id = json_response['scan_id']
                except:
                    scan_id = 'No Info'
                try:
                    score = str(json_response['positives']) + '/' + str(json_response['total'])
                except:
                    score = 'No Info'
                try:
                    md5 = json_response['md5']
                except:
                    md5 = 'No Info'
                try:
                    sha256 = json_response['sha256']
                except:
                    sha256 = 'No Info'
                try:
                    sha1 = json_response['sha1']
                except:
                    sha1 = 'No Info'
                try:
                    permalink = json_response['permalink']
                except:
                    permalink = 'No Info'
                try:
                    while (True):
                        if json_response['response_code'] != -2:
                            for data in json_response['scans']:
                                if json_response['scans'][data]['detected'] == True:
                                    blacklisted_by.append(data)
                            break
                        else:
                            time.sleep(30)
                except:
                    blacklisted_by = ['No Info']

            elif response.status_code == 204:
                print('API LIMIT EXCEEDED FOR VIRUSTOTAL')
                scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
            else:
                print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : ' + self.error_status(
                    response.status_code))
                scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []

            for i in [scan_id, score, md5, sha256, sha1, permalink, blacklisted_by]:
                virus_total_list.append(i)

        except requests.exceptions.ConnectionError:
            print('NOT ABLE TO CONNECT TO VIRUSTOTAL')

    def check_filescan(self):
        virus_total_list = []
        t1 = Thread(target=self.virustotal, args=(self.filescan, virus_total_list))
        t1.start()
        t1.join()
        return virus_total_list