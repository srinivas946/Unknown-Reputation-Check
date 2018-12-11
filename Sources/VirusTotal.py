import csv, os, requests

# -----------------------------------------------------------
#   PARENT CLASS FOR URL CHECK , FILE SCAN , AND HASH CHECK
# -----------------------------------------------------------
class VirusTotal:
    def __init__(self, API_KEY):
        self.API_KEY = API_KEY

    def error_status(self, error_code):
        error_dict = {204:'LIMIT EXCEEDED', 403:'FORBIDDEN ERROR'}
        try:
            return error_dict[error_code]
        except:
            return 'ERROR IN MAKING HTTP CALL TO VIRUS TOTAL. ERROR CODE : '+str(error_code)

# ---------------------------------------------
#   CHILD CLASS: SINGLE OR MULTIPLE URL CHECKS
# ---------------------------------------------
class UrlCheck(VirusTotal):

    def __init__(self, API_KEY, api, mode, url=None, urlfile=None):
        VirusTotal.__init__(self, API_KEY)
        self.api = api
        self.mode = mode
        if url != None:
            self.url = url
        if urlfile != None:
            self.urlfile = urlfile

    def check_url(self):
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        if self.mode == 'Single':
            url, scan_id, score, blacklist_by, permalink = '', '', '', [], ''
            params = {'apikey': self.API_KEY, 'resource': self.url}
            try:
                response = requests.post(self.api, params=params, headers=headers)
                if response.status_code != 204:
                    try:
                        json_response = response.json()
                        while(True):
                            if json_response['response_code'] != -2:
                                try:
                                    url = self.url
                                except:
                                    url = 'No Info'
                                try:
                                    score = str(json_response['positives'])+'/'+str(json_response['total'])
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
                    print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : '+self.error_status(response.status_code))
                    url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
                return url, scan_id, score, blacklist_by, permalink

            except requests.exceptions.ConnectionError:
                print('NOT ABLE TO CONNECT TO VIRUSTOTAL')

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            with open(self.urlfile, 'r', encoding='utf-8') as csvfile:
                csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                url, scan_id, score, blacklist_by, permalink = '', '', '', [], ''
                params = {'apikey': self.API_KEY, 'resource': row[0]}
                try:
                    response = requests.post(self.api, params=params, headers=headers)
                    if response.status_code != 204:
                        try:
                            json_response = response.json()
                            while (True):
                                if json_response['response_code'] != -2:
                                    try:
                                        url = row[0]
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
                            url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], 'No Info'
                    elif response.status_code == 204:
                        print('API LIMIT EXCEEDED')
                        url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], 'No Info'
                    else:
                        print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : ' + self.error_status(response.status_code))
                        url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], 'No Info'
                    data_list.append([url, scan_id, score, blacklist_by, permalink])

                except requests.exceptions.ConnectionError:
                    print('NOT ABLE TO CONNECT TO VIRUSTOTAL')

            # ============= WRITE CSV ================
            fields = ['URL', 'SCAN_ID', 'SCORE', 'BLACKLISTED BY', 'LINK TO VIRUSTOTAL']
            write_file = self.urlfile.replace(self.urlfile.split('/')[-1], 'virustotal_url_scan.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start ' + write_file)
            return str(write_file) + ' IS UPDATED WITH THE URL SCAN RESULTS'


# ----------------------------------------------
#   CHILD CLASS: HASH CHECK SINGLE AND MUTIPLES
# ----------------------------------------------
class HashCheck(VirusTotal):

    def __init__(self, API_KEY, api, mode, hash=None, hashfile=None):
        VirusTotal.__init__(self, API_KEY)
        self.api = api
        self.mode = mode
        if hash != None:
            self.hash = hash
        if hashfile != None:
            self.hashfile = hashfile

    def check_hash(self):
        if self.mode == 'Single':
            scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = '', '', '', '', '', '', []
            params = {'apikey': self.API_KEY, 'resource': self.hash}
            headers = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }
            try:
                response = requests.get(self.api, params=params, headers=headers)
                if response.status_code != 204:
                    json_response = response.json()

                    try:
                        scan_id = json_response['scan_id']
                    except:
                        scan_id = 'No Info'
                    try:
                        score = str(json_response['positives'])+'/'+str(json_response['total'])
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
                    print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : '+self.error_status(response.status_code))
                    scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                return scan_id, score, md5, sha256, sha1, permalink, blacklisted_by

            except requests.exceptions.ConnectionError:
                print('NOT ABLE TO CONNECT TO VIRUSTOTAL')

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            if (os.path.getsize(self.hashfile)/(1024*1024)) <= 32:
                with open(self.hashfile, 'r', encoding='utf-8') as csvfile:
                    csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                    csv_data = list(csvread)
                data_list = []
                headers = {
                    "Accept-Encoding": "gzip, deflate",
                    "User-Agent": "gzip,  My Python requests library example client or username"
                }
                for row in csv_data:
                    scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = '', '', '', '', '', '', []
                    params = {'apikey': self.API_KEY, 'resource': row[0]}
                    try:
                        response = requests.get(self.api, params=params, headers=headers)
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
                            print('API LIMIT EXCEEDED FOR VIRUSTOTAL')
                            scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                        else:
                            print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : '+self.error_status(response.status_code))
                            scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                        data_list.append([scan_id, score, md5, sha256, sha1, blacklisted_by, permalink])

                    except requests.exceptions.ConnectionError:
                        print('UNABLE TO CONNECT IPVOID')

                # ============= WRITE CSV ================
                fields = ['SCAN_ID', 'SCORE', 'MD5', 'SHA256', 'SHA1', 'BLACKLSITED BY', 'LINK TO VIRUSTOTAL']
                write_file = self.hashfile.replace(self.hashfile.split('/')[-1], 'virustotal_hash_check.csv')
                with open(write_file, 'w') as csvwritefile:
                    csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                    csvwrite.writerow(fields)
                    csvwrite.writerows(data_list)
                os.system('start ' + write_file)
                return str(write_file) + ' IS UPDATED WITH THE IP REPUTATION RESULTS'
            else:
                print('FILE SIZE IS TOO LARGE MAKE SURE FILE SIZE LESS THAN OR EQUAL TO 32MB')

# -----------------------------------------------------------
#   CHILD CLASS: FILE HASH SCAN SINLGE AND MULTIPLE FILES
# -----------------------------------------------------------
class FileHash(VirusTotal):

    def __init__(self, API_KEY, api_list, mode, singlefile=None, multifile=None):
        VirusTotal.__init__(self, API_KEY)
        self.api_list = api_list
        self.mode = mode
        if singlefile != None:
            self.singlefile = singlefile
        if multifile != None:
            self.multifile = multifile

    def scan_files(self):
        headers = {"Accept-Encoding": "gzip, deflate", }
        if self.mode == 'Single':
            scan_id, score, md5, sha256, sha1, permalink, blacklisted_by  = '', '', '', '', '', '', []
            files = {'file': (self.singlefile, open(self.singlefile, 'rb'))}
            params = {'apikey': self.API_KEY}
            try:
                response = requests.post(self.api_list[0], files=files, params=params)
                if response.status_code != 204:
                    json_response = response.json()
                    resource = json_response['resource']
                    params = {'apikey': self.API_KEY, 'resource': resource}
                    response = requests.get(self.api_list[1], params=params, headers=headers)
                    json_response = response.json()
                    try:
                        scan_id = json_response['scan_id']
                    except:
                        scan_id = 'No Info'
                    try:
                        score = str(json_response['positives'])+'/'+str(json_response['total'])
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
                        blacklisted_by = ['No Info']

                elif response.status_code == 204:
                    print('API LIMIT EXCEEDED FOR VIRUSTOTAL')
                    scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                else:
                    print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : '+self.error_status(response.status_code))
                    scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []

                return scan_id, score, md5, sha256, sha1, permalink, blacklisted_by

            except requests.exceptions.ConnectionError:
                print('NOT ABLE TO CONNECT TO VIRUSTOTAL')

        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            if (os.path.getsize(self.multifile)/(1024*1024)) <= 32:
                with open(self.multifile, 'r', encoding='utf-8') as csvfile:
                    csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                    csv_data = list(csvread)
                data_list, resource = [], []
                for row in csv_data:
                    scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = '', '', '', '', '', '', []
                    files = {'file': (row[0], open(row[0], 'rb'))}
                    params = {'apikey': self.API_KEY}
                    try:
                        resp = requests.post(self.api_list[0], files=files, params=params)
                        if resp.status_code != 204:
                            json_res = resp.json()
                            resource.append(json_res['resource'])
                        elif resp.status_code == 204:
                            print('API LIMIT EXCEEDED')
                        else:
                            print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : '+self.error_status(resp.status_code))

                    except requests.exceptions.ConnectionError:
                        print('NOT ABLE TO CONNECT TO VIRUSTOTAL')
                for res in resource:
                    params = {'apikey': self.API_KEY, 'resource': res}
                    try:
                        response = requests.get(self.api_list[1], params=params, headers=headers)
                        if response.status_code != 204:
                            try:
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
                                    blacklisted_by = ['No Info']

                                data_list.append([scan_id, score, md5, sha256, sha1, permalink, blacklisted_by])
                            except ValueError:
                                scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []

                        elif response.status_code == 204:
                            print('API LIMIT EXCEEDED FOR VIRUSTOTAL')
                            scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                        else:
                            print('ERROR WHILE CONNECTING TO VIRUSTOTAL, REASON FOR ERROR : '+self.error_status(response.status_code))
                            scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []

                        data_list.append([scan_id, score, md5, sha256, sha1, blaclisted_by, permalink])
                    except requests.exceptions.ConnectionError:
                        print('NOT ABLE TO CONNECT TO VIRUSTOTAL')

                # ============= WRITE CSV ================
                fields = ['SCAN_ID', 'SCORE', 'MD5', 'SHA256', 'SHA1', 'BLACKLSITED BY', 'LINK TO VIRUSTOTAL']
                write_file = self.multifile.replace(self.multifile.split('/')[-1], 'virustotal_scan_file.csv')
                with open(write_file, 'w') as csvwritefile:
                    csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                    csvwrite.writerow(fields)
                    csvwrite.writerows(data_list)
                os.system('start ' + write_file)
                return str(write_file) + ' IS UPDATED WITH THE FILE SCAN RESULTS'
            else:
                print('FILE IS TOO LARGE MAKE SURE FILE SIZE LESS THAN OR EQUAL TO 32MB')
