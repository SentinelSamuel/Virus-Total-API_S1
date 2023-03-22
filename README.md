# PyProjects_S1

Don't forget to replace VIRUS-TOTAL-API-KEY in virustotal-sha256-to-sha1.py

## Installation : 
```
git clone https://github.com/SentinelSamuel/PyProjects_S1.git
cd PyProjects_S1
pip install -r requirements.txt
chmod +x virustotal-sha256-to-sha1-md5.py
```
![image](https://user-images.githubusercontent.com/114468569/226891473-ddef22a4-1ef7-408a-acb6-7acd8adb3558.png)

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

Or mutliple sha256 in a text file : 
```
virustotal-sha256-to-sha1.py -f exemple.txt
# Or 
virustotal-sha256-to-sha1.py --file exemple.txt
```
![image](https://user-images.githubusercontent.com/114468569/226567548-dd192d3a-f34b-42ea-9450-1002f365aab4.png)
