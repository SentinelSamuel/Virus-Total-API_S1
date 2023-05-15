<p align="center">
    <img src="https://user-images.githubusercontent.com/114468569/236483898-d9d94370-3a77-4262-8349-f592b859f3f9.png" alt="drawing" style="width:400px;">
</p>

<div align="center">
    <h1> 
        Virus-Total API S1
    </h1>
</div>


<p align="center">
    Retrieves the hashes corresponding to a list of hashes in a text file <br/>
</p>
<br />
<br />
<br />

Don't forget to replace VIRUS-TOTAL-API-KEY in virustotal-sha256-to-sha1.py

## Installation : 
```
git clone https://github.com/SentinelSamuel/Virus-Total-API_S1.git
cd Virus-Total-API_S1/
pip install -r requirements.txt
chmod +x virustotal-sha256-to-sha1-md5.py
```
![image](https://user-images.githubusercontent.com/114468569/229522908-f09e53eb-fc5b-42c1-94f0-37bb080e0e11.png)

## Usage : 
### For one sha256 : 
```
virustotal-sha256-to-sha1.py 8c6a0698e75ed567d22079534fd962c7b9f59ae5cdaf7c5dccc32c7797fe3e7a --all
```
![image](https://user-images.githubusercontent.com/114468569/229522548-2f762810-50ed-4573-a3a9-e74e7116c506.png)

### For multiple sha256 : 
```
virustotal-sha256-to-sha1.py e5001abcf959b9ac53cf6dc4bb6e699a928fa61cf9fde88eb4405fdc09319a76 ecbc508d4243009ff7d6a222c6b41298df2e99e2e695ce3858be2b1e27cacf9c 8c6a0698e75ed567d22079534fd962c7b9f59ae5cdaf7c5dccc32c7797fe3e7a --all
```
![image](https://user-images.githubusercontent.com/114468569/229523907-d646dcfb-650e-4ec4-b62b-ce653b8efe27.png)

Or mutliple sha256 in a text file and printing file extension md5 and sha1 only : 
```
virustotal-sha256-to-sha1.py -f exemple.txt --file-extension --md5 --sha1
# Or 
virustotal-sha256-to-sha1.py --file exemple.txt --file-extension --md5 --sha1
```
![image](https://user-images.githubusercontent.com/114468569/226892925-5ae76f53-06ee-4461-a029-d0f352e14034.png)
