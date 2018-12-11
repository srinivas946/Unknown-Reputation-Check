import base64, requests, csv, os

# ---------------------------------------------------------------------
#   PARENT CLASS FOR IP_CHECK, DOMAIN_CHECK, URL_CHECK AND HASH_CHECK
# ---------------------------------------------------------------------
class ibm:
    def __init__(self, API_KEY, API_PASSWORD):
        self.API_KEY = API_KEY
        self.API_PASSWORD = API_PASSWORD

    def encode_authorization(self):
        pass_data = self.API_KEY+':'+self.API_PASSWORD
        data = base64.b64encode(pass_data.encode())
        return str(data.decode('utf-8'))

    def headers(self):
        header = {"Authorization": "Basic "+self.encode_authorization(), "Content-Type":"application/json"}
        return header

    def error_status(self, error_code):
        error_dict = {400: 'INVALID API KEY FORMAT', 401: 'UNAUTHORIZED', 402: 'YOUR MONTHLY QUOTA EXCEEDED',
                      403: 'ACCESS DENIED', 404: 'API KEY NOT FOUND', 406: 'NO ACCEPTABLE TYPE SPECIFIED',
                      429: 'RATE LIMIT', 500: 'INTERNAL ERROR'}
        try:
            return error_dict[error_code]
        except:
            return 'ERROR IN MAKING API CALL TO IBM X FORCE. ERROR CODE : '+str(error_code)

    def is_valid_ip(self, ip_add):
        ip = ip_add.strip()
        try:
            if (int(str(ip).split('.')[0]) == 10) or (int(str(ip).split('.')[0]) == 172 and int(str(ip).split('.')[1]) in range(16, 31)) or (int(str(ip).split('.')[0]) == 192 and int(str(ip).split('.')[1]) == 168):
                return False
            else:
                return True
        except:
            print('INVALID IPADDRESS')
            return False


# ------------------------------------------------
#   IP REPUTATION CHECK INHERITED FROM IBM CLASS
#  -----------------------------------------------
class IPCheck(ibm):
    def __init__(self, API_KEY, API_PASSWORD, api, mode, ip=None, ipfile=None):
        ibm.__init__(self, API_KEY=API_KEY, API_PASSWORD=API_PASSWORD)
        self.mode = mode
        self.api = api
        if ip != None:
            self.ip = ip
        if ipfile != None:
            self.ipfile = ipfile

    def check_ip(self):
        if self.mode == 'Single':
            try:
                ip = score = country, category = '', []
                if self.is_valid_ip(self.ip):
                    response = requests.get(self.api+self.ip, headers = self.headers())
                    if response.status_code == 200:
                        json_response = response.json()
                        try:
                            ip = json_response['ip']
                        except:
                            ip = 'No Info'
                        try:
                            score = str(json_response['score'])+' Out of 10'
                        except:
                            score = 'No Info'
                        try:
                            country = json_response['history'][0]['geo']['country']
                        except:
                            country = 'No Info'
                        try:
                            category_data = json_response['categoryDescriptions']
                            if len(category_data)  != 0:
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
                        print('ERROR IN IBM X FORCE : '+self.error_status(response.status_code))
                        ip, score, country, category = self.ip, 'No Info', 'No Info', 'No Info'

                    return ip, score, country, category

                else:
                    print('PRIVATE IP ADDRESS')
                    ip, score, country, category = self.ip, 'No Info', 'No Info', 'No Info'

            except requests.exceptions.ConnectionError:
                print('CHECK YOUR INTERNET CONNECTION')

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            with open(self.ipfile, 'r', encoding='utf-8') as csvfile:
                csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                try:
                    ip = score = country, category = '', []
                    if self.is_valid_ip(row[0]):
                        response = requests.get(self.api + row[0], headers=self.headers())
                        if response.status_code == 200:
                            json_response = response.json()
                            try:
                                ip = json_response['ip']
                            except:
                                ip = 'No Info'
                            try:
                                score = str(json_response['score'])+' Out of 10'
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
                            data_list.append([ip, score, country, str(category).replace('[', '').replace(']', '')])
                        else:
                            print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                            ip, score, country, category = self.ip, 'No Info', 'No Info', 'No Info'
                            data_list.append([ip, score, country, category])
                    else:
                        ip, score, country, category = self.ip, 'No Info', 'No Info', 'No Info'
                        data_list.append([ip, 'PRIVATE IP', 'PRIVATE IP', 'PRIVATE IP'])

                except requests.exceptions.ConnectionError:
                    print('CHECK YOUR INTERNET CONNECTION')
            # ============= WRITE CSV ================
            fields = ['IPADDRESS', 'IP_SCORE', 'IP_COUNTRY', 'IP_CATEGORY']
            write_file_clue = self.ipfile.split('/')[-1]
            write_file = self.ipfile.replace(write_file_clue, 'ibm_ip_reputation.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start '+write_file)
            return str(write_file)+' IS UPDATED WITH THE IP REPUTATION RESULTS'


# -----------------------------------------------------
#   DOMAIN REPUTATION CHECK INHERITED FROM IBM CLASS
# -----------------------------------------------------
class DomainCheck(ibm):
    def __init__(self, API_KEY, API_PASSWORD, api, mode, domain=None, domainfile=None):
        ibm.__init__(self, API_KEY, API_PASSWORD)
        self.mode = mode
        self.api = api
        if domain != None:
            self.domain = domain
        if domainfile != None:
            self.domainfile = domainfile

    def check_domain(self):
        if self.mode == 'Single':
            try:
                domain = score = country, category = '', []
                response = requests.get(self.api + self.domain, headers=self.headers())
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
                    return domain, score, country, category
                else:
                    print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                    domain, score, country, category = self.domain, 'No Info', 'No Info', 'No Info'
                    return domain, score, country, category
            except requests.exceptions.ConnectionError:
                print('CHECK YOUR INTERNET CONNECTION')

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            with open(self.domainfile, 'r', encoding='utf-8') as csvfile:
                csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                try:
                    domain = score = country, category = '', []
                    response = requests.get(self.api + row[0], headers=self.headers())
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
                        data_list.append([domain, score, country, str(category).replace('[', '').replace(']', '')])
                except requests.exceptions.ConnectionError:
                    print('CHECK YOUR INTERNET CONNECTION')
            # ============= WRITE CSV ================
            fields = ['DOMAIN', 'DOMAIN_SCORE', 'DOMAIN_COUNTRY', 'DOMAIN_CATEGORY']
            write_file_clue = self.domainfile.split('/')[-1]
            write_file = self.domainfile.replace(write_file_clue, 'ibm_domain_reputation.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start ' + write_file)
            return str(write_file) + ' IS UPDATED WITH THE DOMAIN REPUTATION RESULTS'

# --------------------------------------------
#   URL STATUS CHECK INHERITED FROM IBM CLASS
# --------------------------------------------
class UrlCheck(ibm):
    def __init__(self, API_KEY, API_PASSWORD, api, mode, url=None, urlfile=None):
        ibm.__init__(self, API_KEY, API_PASSWORD)
        self.api = api
        self.mode = mode
        if url != None:
            self.url = url
        if urlfile != None:
            self.urlfile = urlfile

    def check_url(self):
        if self.mode == 'Single':
            try:
                url = score = country, category = '', []
                response = requests.get(self.api + self.url, headers=self.headers())
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
                return url, score, country, category
            except requests.exceptions.ConnectionError:
                print('CHECK YOUR INTERNET CONNECTION')

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            try:
                with open(self.urlfile, 'r', encoding='utf-8') as csvfile:
                    csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                    csv_data = list(csvread)
            except:
                with open(self.urlfile, 'r', encoding='windows-1252') as csvfile:
                    csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                    csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                try:
                    url = score = country, category = '', []
                    response = requests.get(self.api + row[0], headers=self.headers())
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
                        data_list.append([url, score, country, str(category).replace('[', '').replace(']', '')])
                    else:
                        print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                        data_list.append(['No Info', 'No Info', 'No Info', 'No Info'])
                except requests.exceptions.ConnectionError:
                    print('CHECK YOUR INTERNET CONNECTION')
            # ============= WRITE CSV ================
            fields = ['URL', 'URL_SCORE', 'URL_COUNTRY', 'URL_CATEGORY']
            write_file_clue = self.urlfile.split('/')[-1]
            write_file = self.urlfile.replace(write_file_clue, 'ibm_url_reputation.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start ' + write_file)
            return str(write_file) + ' IS UPDATED WITH THE URL REPUTATION RESULTS'

# ---------------------------------------------
#   HASH VALUE CHECK INHERITED FROM IBM CLASS
# ---------------------------------------------
class HashCheck(ibm):
    def __init__(self, API_KEY, API_PASSWORD, api, mode, hash=None, hashfile=None):
        ibm.__init__(self, API_KEY, API_PASSWORD)
        self.mode = mode
        self.api = api
        if hash != None:
            self.hash = hash
        if hashfile != None:
            self.hashfile = hashfile

    def check_hash(self):
        if self.mode == 'Single':
            try:
                family, type, risk = [], '', ''
                response = requests.get(self.api + self.hash, headers=self.headers())
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

                return self.hash, family, type, risk

            except requests.exceptions.ConnectionError:
                print('CHECK YOUR INTERNET CONNECTION')

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            try:
                with open(self.hashfile, 'r', encoding='utf-8') as csvfile:
                    csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                    csv_data = list(csvread)
            except:
                with open(self.hashfile, 'r', encoding='windows-1252') as csvfile:
                    csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                    csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                try:
                    hash_val, family, type, risk = '',[], '', ''
                    response = requests.get(self.api + row[0], headers=self.headers())
                    if response.status_code == 200:
                        json_response = response.json()
                        hash_val = row[0]
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
                        data_list.append([hash_val, str(family).replace('[', '').replace(']', ''), type, risk])
                    else:
                        print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                        data_list.append(['No Info', 'No Info', 'No Info', 'No Info'])

                except requests.exceptions.ConnectionError:
                    print('CHECK YOUR INTERNET CONNECTION')

            # ============= WRITE CSV ================
            fields = ['HASH', 'HASH_FAMILY', 'HASH_TYPE', 'HASH_RISK']
            write_file_clue = self.hashfile.split('/')[-1]
            write_file = self.hashfile.replace(write_file_clue, 'ibm_hash_reputation.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start ' + write_file)
            return str(write_file) + ' IS UPDATED WITH THE HASH VALUE RESULTS'


