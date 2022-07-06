# AD description password finder

The purpose of this tool is to check if passwords are stored in clear text in the description of Active Directory accounts.

The requirements are :
  - having a copy of the ntds.dit and SYSTEM hive
  
 If you don't have python, you can use the .exe version of the scripts in the binary folder of this repository.
 
### Blue Team use case

You want to check if password are stored in the description field of Active Directory accounts of your organization.

### Internal Pentest/Red Team

Post-exploitation: You successfully dumped the ntds.dit and SYSTEM hive and while cracking the hashes, you want to check if some plain text passwords are available in the description field of Active Directory accounts.

## Requirements
- Python 3
- six
- pycryptodomex

## Install
Install the requirements
~~~
$ git clone https://github.com/AssuranceMaladieSec/AD-description-password-finder.git
$ pip3 install -r requirements.txt
~~~

## Usage
### check_description.py

```
> python check_description.py -h
usage: check_description.py [-h] [-system SYSTEM] [-ntds NTDS] [-ts] [-debug]

optional arguments:
  -h, --help      show this help message and exit
  -system SYSTEM  SYSTEM hive to parse. MANDATORY
  -ntds NTDS      NTDS.DIT file to parse. MANDATORY
  -ts             Adds timestamp to every logging output during hashes extraction
  -debug          Turn DEBUG output ON during hashes extraction



> python check_description.py -ntds ntds\ntds.dit -system ntds\SYSTEM

Extracting hash and descriptions in the ntds

Saving output to ntds/output.ntds

Creating hash file in './output/description_hashes.json' and plain text file in './output/description_plain.json'

Done!

Loading ./output/description_hashes.json

Loading ./output/description_plain.json

Loading ./ntds/output.ntds

We have 6 user's descriptions to analyze

Done! We found 2 password in the accounts description

You can find the results in the file ./results/2022-07-05_11h45_results.txt

That's all folks!
```

## File results example

```
Disabled user - password for the user test-alice2 is in the description: Achanger6Achanger6!
Enabled (probably) user - The password for the user test-alice is in the description: Achanger1Achanger2!
```
## Use of impacket

This tool uses a modified version of the [`secretdump`](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py) code from the [Impacket](https://github.com/SecureAuthCorp/impacket) library.

Impacket is a tool from SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.

## Author
- Alice Climent-Pommeret ([alice.climentpommeret@assurance-maladie.fr](mailto:alice.climentpommeret@assurance-maladie.fr))

## License
GNU GENERAL PUBLIC LICENSE (GPL) Version 3
