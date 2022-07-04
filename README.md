# AD description password finder

The purpose of this tool is to check if passwords are stored in clear text in the description of Active Directory accounts.

The requirements are :
  - Active Directory Module installed on the machine executing "get_description.py"
  - having a copy of the ntds.dit and SYSTEM hive
  
 If you don't have python, you can use the .exe version of the scripts in the binary folder of this repository.
 
### Blue Team use case

You want to check if password are stored in the description field of Active Directory accounts of your organization.

### Internal Pentest/Red Team

You successfully dumped the ntds.dit and SYSTEM hive and while cracking the hashes, you want to check if some plain text passwords are available in the description field of Active Directory accounts.

## Requirements
- Python 3
- six
- pycryptodomex

## Install
Install the requirements
~~~
$ pip3 install -r requirements.txt
~~~

## Usage
### get_description.py

```
> python get_description.py

Launching PowerShell Script to retrieve AD accounts and their descriptions
Requesting domain controller to retrieve all accounts with description
Done! Powershell results to be processed are written in C:\Users\XXX\AD-description-password-finder\output\desc.csv

loading and processing PowerShell results

Creating hash file in './output/description_hashes.json' and plain text file in './output/description_plain.json'

Done!
````

### check_description.py

```
> python check_description.py -h
usage: check_description.exe [-h] [-extract] [-system SYSTEM] [-ntds NTDS] [-ts] [-debug]

optional arguments:
  -h, --help      show this help message and exit
  -extract        extract hashes from NTDS
  -system SYSTEM  SYSTEM hive to parse. MANDATORY if -extract is used
  -ntds NTDS      NTDS.DIT file to parse. MANDATORY if -extract is used
  -ts             Adds timestamp to every logging output during hashes extraction
  -debug          Turn DEBUG output ON during hashes extraction

> python check_description.py -extract -ntds ntds\ntds.dit -system ntds\SYSTEM

Saving output to ntds/output.ntds
Administrateur:500:aad3b435b51404eeaad3b435b51404ee:XYZ:::
Invité:501:aad3b435b51404eeaad3b435b51404ee:XYZ:::
...

INFO:root:Cleaning up...

Starting the Check Description Script

Loading ./output/description_hashes.json

Loading ./output/description_plain.json

Loading ./ntds/output.ntds

We have 3141 hashes of user with description to process

Done! We found 8 password in the accounts description

That's all folks!
```


## Retrieve AD accounts with description 

Execute `get_description.py` (or get_description.exe) in a shell. This will request the Domain Controller using the Powershell script `Get_Desc.ps1`.

Once done, you will find json files stored in the `output` directory. This files will be used by the `check_description.py` script.

<p align="center">
<img src="https://github.com/AssuranceMaladieSec/AD-description-password-finder/blob/main/pics/get_description.png" width="60%" height="60%">  
</p>

## Finding password in descriptions

Case 1: You already extracted the hashes from the ntds using [secretdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) or [gosecretdump.exe](https://github.com/C-Sto/gosecretsdump) just put the file with the hashes in the `ntds` folder. **The name of the file MUST be `output.ntds`**
then execute `check_description.py` (or check_description.exe).

<p align="center">
<img src="https://github.com/AssuranceMaladieSec/AD-description-password-finder/blob/main/pics/convert_ntds.png" width="60%" height="60%">  
</p>

Case 2: You have the `ntds.dit` and `SYSTEM hive` file but the hashes are not extracted yet. Execute `check_description.py -extract -ntds path\to\ntds.dit -system path\to\SYSTEM\hive`

If passwords are discovered in descriptions the results will be put in the `results` directory.
<p align="center">
<img src="https://github.com/AssuranceMaladieSec/AD-description-password-finder/blob/main/pics/check_description.png" width="60%" height="60%">  
</p>

## Use of impacket

This tool uses the [`secretdump`](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py) code of the [Impacket](https://github.com/SecureAuthCorp/impacket) library to extract hashes from the ntds.

Impacket is a tool from SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.

## Author
- Alice Climent-Pommeret ([alice.climentpommeret@assurance-maladie.fr](mailto:alice.climentpommeret@assurance-maladie.fr))

## License
GNU GENERAL PUBLIC LICENSE (GPL) Version 3
