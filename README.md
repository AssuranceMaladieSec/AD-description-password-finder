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

We have 9 user's descriptions to analyze

Done!

We found 4 CONFIRMED password in the accounts description

2 accounts are SUSPECTED of exposing their passwords and need to be verified by a HUMAN

You can find the results in the file ./results/2022-07-21_17h8_results.txt

That's all folks!
```

## File results example

```
CONFIRMED_LEAK - Disabled user - password for user adm-test-alice2 found in description: Achanger6Achanger6!
CONFIRMED_LEAK - Enabled (probably) user - password for user adm-test-alice found in description: Achanger1Achanger2!
SUSPECTED_LEAK - Enabled (probably) user - SUSPECTED password for user anakin in the description: here we go "pwd=test01!"
SUSPECTED_LEAK - Enabled (probably) user - SUSPECTED password for user ahsoka in the description: The new one for test (password=test054!)
CONFIRMED_LEAK - Enabled (probably) user - password for user mariatest02 found in description: test02!
CONFIRMED_LEAK - Enabled (probably) user - password for user blanqui found in description: woof01!
```
## Use of impacket

This tool uses a modified version of the [`secretdump`](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py) code from the [Impacket](https://github.com/SecureAuthCorp/impacket) library.

Impacket is a tool from SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.

## Author
- Alice Climent-Pommeret ([alice.climentpommeret@assurance-maladie.fr](mailto:alice.climentpommeret@assurance-maladie.fr))

## License
GNU GENERAL PUBLIC LICENSE (GPL) Version 3
