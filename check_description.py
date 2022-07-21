# -*- coding: utf-8 -*-

# Author : Alice Climent-Pommeret (Pentester @ Caisse Nationale de l'Assurance Maladie)
# Copyright (c) Caisse nationale d'Assurance Maladie
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

from os import path
import json
import re
from datetime import datetime
import argparse
import logging
import hashlib
import json
from impacket.examples import logger
from impacket.examples.secretsdump import LocalOperations, NTDSHashes

try:
    input = raw_input
except NameError:
    pass

class DumpSecrets:
    def __init__(self, options=None):
        self.__useVSSMethod = None
        self.__remoteName = 'LOCAL'
        self.__remoteOps = None
        self.__NTDSHashes = None
        self.__systemHive = options.system
        self.__bootkey = None
        self.__ntdsFile = options.ntds
        self.__history = None
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = 'ntds/output'
        self.__justDCNTLM = True
        self.__justUser = None
        self.__pwdLastSet = None
        self.__printUserStatus= None
        self.__resumeFileName = None
        self.__options = options


    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.__bootkey)

            NTDSFileName = self.__ntdsFile

            self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                            noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                            useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                            pwdLastSet=self.__pwdLastSet,
                                            outputFileName=self.__outputFileName, justUser=self.__justUser,
                                            printUserStatus= self.__printUserStatus)
            try:
                description_ntds = self.__NTDSHashes.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error(e)

            self.cleanup()
            return description_ntds

        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        #logging.info('Cleaning up... ')
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()

date = datetime.date(datetime.now())
filename = f"./results/{date}_{datetime.now().hour}h{datetime.now().minute}_results.txt"
    
def search_pass(ntds, hashes, plain, filename, list_disabled, list_to_check):
    processed = len(hashes)
    found = 0
    found_to_check = 0
    
    print("\nWe have %s user's descriptions to analyze" % processed)
    # for each entry from csv file
    with open(filename, mode='w',encoding='utf8') as f:
        for entry in hashes:
        # if entry in ntds and hash NT of the entry match a description hash
            try:
                if (ntds[entry] in hashes[entry]):
                    # Get the index to retrieve the plain text
                    index = hashes[entry].index(ntds[entry])
                    if entry in list_disabled:
                        f.write(f"CONFIRMED_LEAK - Disabled user - password for user {entry} found in description: {plain[entry][index]}\n")
                    else:
                        f.write(f"CONFIRMED_LEAK - Enabled (probably) user - password for user {entry} found in description: {plain[entry][index]}\n")
                    found += 1
                else:
                    if entry in list_to_check:
                        if entry in list_disabled:
                            f.write(f"SUSPECTED_LEAK - Disabled user - SUSPECTED password for user {entry} in the description: {plain[entry][0]}\n")
                        else:
                            f.write(f"SUSPECTED_LEAK - Enabled (probably) user - SUSPECTED password for user {entry} in the description: {plain[entry][0]}\n")
                        found_to_check += 1
            except:
                continue
                
    return found, found_to_check
    
def load_description(filename):
    dict_from_json = {}
    with open(filename) as json_file:
        dict_from_json = json.load(json_file)
    return dict_from_json

def load_ntds(filename):
    dict_from_ntds = {}
    with open(filename, mode='r',encoding='utf8') as f:
        for line in f:
            # split the ntds entry
            entry = line.strip().split(":")
            # split the account field to separate domain and username
            domain_and_user = entry[0].split("\\")         
            # if there is a domain and the account it not a machine account
            if (len(domain_and_user) > 1) and (domain_and_user[1][-1] != "$"):
                dict_from_ntds[domain_and_user[1].lower()] = entry[3]
            # if there is no domain and the account is not a machine account
            elif (len(domain_and_user) == 1) and (domain_and_user[0][-1] != "$"):
                dict_from_ntds[domain_and_user[0].lower()] = entry[3]
                
    return dict_from_ntds

def nt_hash(string):
    hash = hashlib.new('md4', string.encode('utf-16le')).hexdigest()
    return hash
    
def hashes_desc(dic_csv):
    dict_hashes_desc = {}
    dict_plain_desc = {}
    to_check = []
    
    #For each user 
    for elem in dic_csv:
	
	    # Search for password pattern
        pass_string_exist = re.search("[^a-zA-Z0-9]?(?:pass|passe|passwd|password|mdp|pwd)\s?(?::|=)\s?(\S+)", dic_csv[elem], flags=re.IGNORECASE)
        
        # Split the description in substring (separator is space)
        sub_str = dic_csv[elem].split()

        # If password pattern matched
        if pass_string_exist is not None:
            # Extract probable password
            sub_str.append(pass_string_exist.groups()[0])
            # Add account in the list of potential leaks (aka something we missed like trailing ")" or something something)
            to_check.append(elem)

        #retrieve the whole description too
        desc = dic_csv[elem]
        #convert into NT hash the whole description and put it at first element of the user entry in the new dico
        dict_hashes_desc[elem] = [nt_hash(desc)]
        #Equivalent operation but in plain text in plain dico
        dict_plain_desc[elem] = [desc]
        
        #For each sub string in the description
        for item in sub_str:
            #convert in NT hash the substring and add it in the list for the user entry in the hash dico
            dict_hashes_desc[elem].append(nt_hash(item))
            #same thing but plain text
            dict_plain_desc[elem].append(item)
    return dict_hashes_desc, dict_plain_desc, to_check
  
def write_dico_json(dico, filename):
    f = open(filename, "w")
    json.dump(dico, f)
    f.close()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help = True)
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse. MANDATORY')
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse. MANDATORY')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output during hashes extraction')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON during hashes extraction')
    options = parser.parse_args()

    #logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


    if (options.ntds == None) or (options.system == None):
        print("\nParameters -ntds and -system are mandatory!\n")
        exit(1)
    else:
        dumper = DumpSecrets(options)
        try:
            print("\nExtracting hash and descriptions in the ntds\n")
            description_ntds, list_description_disabled = dumper.dump()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)

    print("\nCreating hash file in './output/description_hashes.json' and plain text file in './output/description_plain.json'")
    dict_hashes, dict_plain, list_to_check = hashes_desc(description_ntds)
    write_dico_json(dict_hashes, "./output/description_hashes.json")
    write_dico_json(dict_plain, "./output/description_plain.json")
    print("\nDone!")

    print("\nLoading ./output/description_hashes.json")
    if not path.exists("./output/description_hashes.json"):
        print("\nError! ./output/description_hashes.json doesn't exist")
        exit(1)
    else:
        dict_hashes = load_description("./output/description_hashes.json")

    print("\nLoading ./output/description_plain.json")
    if not path.exists("./output/description_plain.json"):
        print("\nError! ./output/description_plain.json  doesn't exist")
        exit(1)       
    else:
        dict_plain = load_description("./output/description_plain.json")

    print("\nLoading ./ntds/output.ntds")
    if not path.exists("./ntds/output.ntds"):
        print("\nError! ./ntds/output.ntds")
        print("\nUse the -extract option to generate the output.ntds file from ntds.dit")
        exit(1)              
    else:
        dict_ntds = load_ntds("./ntds/output.ntds")
    
    pass_found, tocheck_found = search_pass(dict_ntds, dict_hashes, dict_plain, filename, list_description_disabled, list_to_check)

    print("\nDone!")
    if ( (pass_found > 0) or (tocheck_found > 0) ):
        print("\nWe found %s CONFIRMED password in the accounts description" % pass_found)
        print("\n%s accounts are SUSPECTED of exposing their passwords and need to be verified by a HUMAN" % tocheck_found)
        print("\nYou can find the results in the file %s" % filename)
    else:
        print("\nNo plain text password found in accounts descriptions")
    print("\nThat's all folks!")
    
