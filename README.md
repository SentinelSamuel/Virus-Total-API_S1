# PyProjects_S1

Don't forget to replace VIRUS-TOTAL-API-KEY in virustotal-sha256-to-sha1.py

## Installation : 
```
git clone https://github.com/SentinelSamuel/PyProjects_S1.git
cd PyProjects_S1
pip install -r requirements.txt
chmod +x virustotal-sha256-to-sha1-md5.py
```
![image](https://user-images.githubusercontent.com/114468569/226921890-d7519077-bb25-4193-bf2c-348e4ed1a53e.png)

## Usage : 
### For one sha256 : 
```
virustotal-sha256-to-sha1.py 8c6a0698e75ed567d22079534fd962c7b9f59ae5cdaf7c5dccc32c7797fe3e7a --all
```
![image](https://user-images.githubusercontent.com/114468569/226892086-a434f19c-a872-442c-b0fd-caf316d9ab5a.png)

### For multiple sha256 : 
```
virustotal-sha256-to-sha1.py e5001abcf959b9ac53cf6dc4bb6e699a928fa61cf9fde88eb4405fdc09319a76 ecbc508d4243009ff7d6a222c6b41298df2e99e2e695ce3858be2b1e27cacf9c 8c6a0698e75ed567d22079534fd962c7b9f59ae5cdaf7c5dccc32c7797fe3e7a --all
```
![image](https://user-images.githubusercontent.com/114468569/226892513-adf571eb-ff79-4f15-9d80-3230b521b2d3.png)

Or mutliple sha256 in a text file and printing file extension md5 and sha1 only : 
```
virustotal-sha256-to-sha1.py -f exemple.txt --file-extension --md5 --sha1
# Or 
virustotal-sha256-to-sha1.py --file exemple.txt --file-extension --md5 --sha1
```
![image](https://user-images.githubusercontent.com/114468569/226892925-5ae76f53-06ee-4461-a029-d0f352e14034.png)
