import csv, os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup as bs
import time
# --------------------------------------------------------------
#   TALOS PARENT CLASS FOR IPCHECK, DOMAIN CHECK AND URL CHECK
# --------------------------------------------------------------
class talos:

    def __init__(self, driver_path):
        self.driver_path = driver_path

    def selenium_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        driver = webdriver.Chrome(executable_path='C:/Users/Srinivas.K/Downloads/new/chromedriver.exe',
                                  chrome_options=chrome_options)
        return driver

    def error_status(self, error_code):
        error_dict = {400: 'BAD REQUEST', 401: 'UNAUTHORIZED', 403: 'ACCESS DENIED/FORBIDDEN', 404: 'NOT FOUND', 405:'METHOD NOT ALLOWED', 406: 'NO ACCEPTABLE TYPE SPECIFIED',
                      408: 'REQUEST TIME OUT', 415:'UNSUPPORTED MEDIA TYPE', 429: 'RATE LIMIT', 500: 'INTERNAL ERROR', 502: 'BAD GATEWAY', 503:'SERVICE UNAVAILABLE', 504:'GATEWAY TIMEOUT', 505:'HTTP VERSION NOT SUPPORTED'}
        try:
            return error_dict[error_code]
        except:
            return 'ERROR IN MAKING HTTP CALL TO IPVOID. ERROR CODE : '+str(error_code)

    def is_valid_ip(self, ip_add):
        ip = ip_add.strip()
        try:
            if (int(str(ip).split('.')[0]) == 10) or (int(str(ip).split('.')[0]) == 172 and int(str(ip).split('.')[1]) in range(16, 31)) or int((str(ip).split('.')[0]) == 192 and int(str(ip).split('.')[1]) == 168):
                return False
            else:
                return True
        except:
            return 'Not IP'

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

# ---------------------------------------------------------------------
#   IPCHECK CHILD CLASS FOR CHECKING THE REPUTAITON OF IPADDRESS
# ---------------------------------------------------------------------
class IPCheck(talos):

    def __init__(self, driver_path, http_path, mode, ip=None, ipfile=None):
        talos.__init__(self, driver_path)
        self.http_path = http_path
        self.mode = mode
        if ip != None:
            self.ip = ip
        if ipfile != None:
            self.ipfile = ipfile

    def check_ip(self):
        driver = self.selenium_driver()
        if self.mode == 'Single':
            driver.get(self.http_path+self.ip)
            response = driver.page_source
            driver.quit()
            soap = bs(response, 'html.parser')
            ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
            email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
            ip, host, domain = self.basic_details(soap, ip, host, domain)
            spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
            return ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            with open(self.ipfile, 'r', encoding='utf-8') as csvfile:
                csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                print(self.http_path+row[0])
                driver.get(self.http_path+row[0])
                response = driver.page_source
                soap = bs(response, 'html.parser')
                ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
                email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
                time.sleep(3)
                ip, host, domain = self.basic_details(soap, ip, host, domain)
                time.sleep(3)
                spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
                time.sleep(3.5)
                ctry, city = self.location_check(soap, ctry, city)
                time.sleep(3.5)
                data_list.append([ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change])
            driver.quit()
            # ============= WRITE CSV ================
            fields = ['IPADDRESS', 'HOST NAME', 'DOMAIN', 'COUNTRY', 'CITY', 'EMAIL_REPUTATION', 'WEB_REPUTATION', 'WEIGHT_REPUTATION', 'SPAM_LEVEL', 'EMAIL_VOLUME', 'VOLUME_CHANGE']
            write_file = self.ipfile.replace(self.ipfile.split('/')[-1], 'cisco_talos_ip_reputation.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start ' + write_file)
            return str(write_file) + ' IS UPDATED WITH THE IP REPUTATION RESULTS'

# --------------------------------------
#  DOMAIN CHECK CHILD CLASS FOR TALOS
# --------------------------------------
class DomainCheck(talos):

    def __init__(self, driver_path, http_path, mode, domain=None, domainfile=None):
        talos.__init__(self, driver_path)
        self.http_path = http_path
        self.mode = mode
        if domain != None:
            self.domain = domain
        if domainfile != None:
            self.domainfile = domainfile

    def check_domain(self):
        driver = self.selenium_driver()
        if self.mode == 'Single':
            driver.get(self.http_path + self.domain)
            response = driver.page_source
            driver.quit()
            soap = bs(response, 'html.parser')
            ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
            email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
            ip, host, domain = self.basic_details(soap, ip, host, domain)
            spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
            return ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            with open(self.domainfile, 'r', encoding='utf-8') as csvfile:
                csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                print(self.http_path + row[0])
                driver.get(self.http_path + row[0])
                response = driver.page_source
                soap = bs(response, 'html.parser')
                ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
                email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
                time.sleep(3)
                ip, host, domain = self.basic_details(soap, ip, host, domain)
                time.sleep(3)
                spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
                time.sleep(3.5)
                ctry, city = self.location_check(soap, ctry, city)
                time.sleep(3.5)
                data_list.append(
                    [ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change])
            driver.quit()
            # ============= WRITE CSV ================
            fields = ['IPADDRESS', 'HOST NAME', 'DOMAIN', 'COUNTRY', 'CITY', 'EMAIL_REPUTATION', 'WEB_REPUTATION',
                      'WEIGHT_REPUTATION', 'SPAM_LEVEL', 'EMAIL_VOLUME', 'VOLUME_CHANGE']
            write_file = self.domainfile.replace(self.domainfile.split('/')[-1], 'cisco_talos_domain_reputation.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start ' + write_file)
            return str(write_file) + ' IS UPDATED WITH THE DOMAIN REPUTATION RESULTS'

# -----------------------------------------
#   URL CHECK CHILD CLASS FOR TALOS
# -----------------------------------------
class UrlCheck(talos):

    def __init__(self, driver_path, http_path, mode, url=None, urlfile=None):
        talos.__init__(self, driver_path)
        self.http_path = http_path
        self.mode = mode
        if url != None:
            self.url = url
        if urlfile != None:
            self.urlfile = urlfile

    def check_url(self):
        driver = self.selenium_driver()
        if self.mode == 'Single':
            driver.get(self.http_path + self.url)
            response = driver.page_source
            driver.quit()
            soap = bs(response, 'html.parser')
            ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
            email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
            ip, host, domain = self.basic_details(soap, ip, host, domain)
            spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
            return ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            with open(self.urlfile, 'r', encoding='utf-8') as csvfile:
                csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                print(self.http_path + row[0])
                driver.get(self.http_path + row[0])
                response = driver.page_source
                soap = bs(response, 'html.parser')
                ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change = '', '', '', '', '', '', '', '', {}, {}, {}
                email_rep, web_rep, wght_rep = self.reputation_check(soap, email_rep, web_rep, wght_rep)
                time.sleep(3)
                ip, host, domain = self.basic_details(soap, ip, host, domain)
                time.sleep(3)
                spam_level, email_volume, vol_change = self.score(soap, spam_level, email_volume, vol_change)
                time.sleep(3.5)
                ctry, city = self.location_check(soap, ctry, city)
                time.sleep(3.5)
                data_list.append(
                    [ip, host, domain, ctry, city, email_rep, web_rep, wght_rep, spam_level, email_volume, vol_change])
            driver.quit()
            # ============= WRITE CSV ================
            fields = ['IPADDRESS', 'HOST NAME', 'DOMAIN', 'COUNTRY', 'CITY', 'EMAIL_REPUTATION', 'WEB_REPUTATION',
                      'WEIGHT_REPUTATION', 'SPAM_LEVEL', 'EMAIL_VOLUME', 'VOLUME_CHANGE']
            write_file = self.urlfile.replace(self.urlfile.split('/')[-1], 'cisco_talos_domain_reputation.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start ' + write_file)
            return str(write_file) + ' IS UPDATED WITH THE DOMAIN REPUTATION RESULTS'

