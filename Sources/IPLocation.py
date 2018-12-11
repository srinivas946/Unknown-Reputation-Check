import requests, os, csv, time
from bs4 import BeautifulSoup as bs
from selenium import webdriver


# -------------------------------------
#   PARENT CLASS FOR LOCATION CHECK
# -------------------------------------
class iplocation:

    def webdriver(self, driver_path, http_path, lat, lon, view_time):
        driver = webdriver.Chrome(executable_path=driver_path)
        driver.get(http_path+lat+', '+lon)
        time.sleep(view_time)
        driver.quit()

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
            if (str(ip).split('.')[0] == '10') or (str(ip).split('.')[0] == '172' and str(ip).split('.')[1] in range(16, 31)) or (str(ip).split('.')[0] == '192' and str(ip).split('.')[1] == '168'):
                return False
            else:
                return True
        except:
            print('INVALID IPADDRESS')
            return False

# ------------------------------------------
#   CHILD CLASS INHERITED FROM IPLOCATION
# ------------------------------------------
class LocationCheck(iplocation):

    def __init__(self, http_url, mode, ip=None, ipfile=None):
        self.http_url = http_url
        self.mode = mode
        if ip != None:
            self.ip = ip
        if ipfile != None:
            self.ipfile = ipfile

    def check_location(self, driver_path=None, http_path=None, view_time=None):
        if self.mode == 'Single':
            if self.is_valid_ip(self.ip):
                try:
                    formdata = {'query': self.ip}
                    response = requests.get(self.http_url, params=formdata)
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
                        if driver_path != None and http_path != None and view_time != None:
                            self.webdriver(driver_path, http_path, lat, lon, view_time)
                        else:
                            return ip, country, city, region, isp, lat, lon
                    else:
                        print('ERROR IN HTTP CONNECTIONS : '+self.error_status(response.status_code))
                        return self.ip, 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info'

                except requests.exceptions.ConnectionError:
                    print('UNBALE TO CONNECT TO IPLOCATION WEBSITE')
                except requests.exceptions.ConnectTimeout:
                    print('CONNECTION TIME OUT')
        elif self.mode == 'Multiple':
            # ========== READ CSV FILE ================
            with open(self.ipfile, 'r', encoding='utf-8') as csvfile:
                csvread = csv.reader((line.replace('\0', '') for line in csvfile))
                csv_data = list(csvread)
            data_list = []
            for row in csv_data:
                if self.is_valid_ip(row[0]):
                    try:
                        formdata = {'query': row[0]}
                        response = requests.get(self.http_url, params=formdata)
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
                            data_list.append([ip, country, city, region, isp, lat, lon])
                        else:
                            print('ERROR IN HTTP CONNECTIONS : ' + self.error_status(response.status_code))
                            data_list.append([row[0], 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info'])
                    except requests.exceptions.ConnectionError:
                        print('UNBALE TO CONNECT TO IPLOCATION WEBSITE')
            # ============= WRITE CSV ================
            fields = ['IPADDRESS', 'IP_COUNTRY', 'IP_CITY', 'IP_REGION', 'ISP', 'LATITUDE', 'LONGITUDE']
            write_file = self.ipfile.replace(self.ipfile.split('/')[-1], 'iplocation_ip_details.csv')
            with open(write_file, 'w') as csvwritefile:
                csvwrite = csv.writer(csvwritefile, lineterminator='\n')
                csvwrite.writerow(fields)
                csvwrite.writerows(data_list)
            os.system('start ' + write_file)
            return str(write_file) + ' IS UPDATED WITH THE IP LOCATION RESULTS'


