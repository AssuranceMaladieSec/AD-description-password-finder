# AD description password finder

The purpose of this tool is to check if passwords are stored in clear text in the desciption of Active Directory accounts.

The requirements are :
  - Active Directory Module installed on the machine executing "get_description.py"
  - having a copy of the ntds 
  
 If you don't have python, you can use the .exe version of the scripts in the binary folder of this repository.

## Retrieve AD accounts with description 

Execute `get_description.py` (or get_description.exe) in a shell. This will request the Domain Controller using the Powershell script `Get_Desc.ps1`.

Once done, you will find json files stored in the `output` directory. This files will be used by the `check_description.py` script.

<p align="center">
<img src="https://github.com/AssuranceMaladieSec/AD-description-password-finder/blob/main/pics/get_description.png" width="60%" height="60%">  
</p>

## Extract hashes from your ntds copy

Extract the hashes of your ntds file using [secretdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) from the impacket project or [gosecretdump.exe](https://github.com/C-Sto/gosecretsdump).

**The result must be put in the `ntds` directory with the name `output.ntds`**

<p align="center">
<img src="https://github.com/AssuranceMaladieSec/AD-description-password-finder/blob/main/pics/convert_ntds.png" width="60%" height="60%">  
</p>

## Finding password in descriptions

Execute `check_description.py` (or check_description.exe).

If passwords are discovered in descriptions the results will be put in the `results` directory.
<p align="center">
<img src="https://github.com/AssuranceMaladieSec/AD-description-password-finder/blob/main/pics/check_description.png" width="60%" height="60%">  
</p>
