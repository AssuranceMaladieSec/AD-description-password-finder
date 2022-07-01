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

import json
from datetime import datetime

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
            

print("\nStarting the Check Description Script")
print("\nLoading ./output/description_hashes.json")
dict_hashes = load_description("./output/description_hashes.json")

print("\nLoading ./output/description_plain.json")
dict_plain = load_description("./output/description_plain.json")

print("\nLoading ./ntds/output.ntds")
dict_ntds = load_ntds("./ntds/output.ntds")
pass_found = search_pass(dict_ntds, dict_hashes, dict_plain, filename)

print("\nDone! We found %s password in the accounts description" % pass_found)
if (pass_found > 0):
    print("\nYou can find the results in the file %s" % filename)
print("\nThat's all folks!")