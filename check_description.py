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
from datetime import datetime
import argparse
import logging
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
                self.__NTDSHashes.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error(e)

            self.cleanup()

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
        logging.info('Cleaning up... ')
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()

date = datetime.date(datetime.now())
filename = f"./results/{date}_{datetime.now().hour}h{datetime.now().minute}_results.txt"
    
def search_pass(ntds, hashes, plain, filename):
    processed = len(hashes)
    found = 0
    
    print("\nWe have %s hashes of user with description to process" % processed)
    # for each entry from csv file
    with open(filename, mode='a',encoding='utf8') as f:
        for entry in hashes:
        # if entry in ntds and hash NT of the entry match a description hash
            try:
                if (ntds[entry] in hashes[entry]):
                    # Get the index to retrieve the plain text
                    index = hashes[entry].index(ntds[entry])
                    f.write(f"The password for the user {entry} is in the description: {plain[entry][index]}\n")
                    found += 1
            except:
                continue
                
    return found
    
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

if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help = True)
    parser.add_argument('-extract', action='store_true', help='extract hashes from NTDS')
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse. MANDATORY if -extract is used')
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse. MANDATORY if -extract is used')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output during hashes extraction')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON during hashes extraction')
    options = parser.parse_args()

    #logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if (options.extract):
        if (options.ntds == None) or (options.system == None):
            print("\nTo use -extract parameters -ntds and -system are mandatory!\n")
            exit(1)
        else:
            dumper = DumpSecrets(options)
            try:
                dumper.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error(e)
    elif (options.ntds != None) or (options.system != None):
        print("\nYou cannot use -ntds and -system parameters without -extract!\n")
        exit(1)

    print("\nStarting the Check Description Script")

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
    
    pass_found = search_pass(dict_ntds, dict_hashes, dict_plain, filename)

    print("\nDone! We found %s password in the accounts description" % pass_found)
    if (pass_found > 0):
        print("\nYou can find the results in the file %s" % filename)
    print("\nThat's all folks!")