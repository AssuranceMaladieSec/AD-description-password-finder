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

import subprocess
import hashlib
import json
import csv

def nt_hash(string):
    hash = hashlib.new('md4', string.encode('utf-16le')).hexdigest()
    return hash
    
def hashes_desc(dic_csv):
    dict_hashes_desc = {}
    dict_plain_desc = {}
    
    #For each user 
    for elem in dic_csv:
        #split the description in substring (separator is space)
        sub_str = dic_csv[elem].split()
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
    return dict_hashes_desc, dict_plain_desc

def run(cmd):
    completed = subprocess.run(["powershell", cmd])
    return completed

def load_description(filename):
    dict_from_csv = {}
    with open(filename, mode='r',encoding='utf8') as inp:
        reader = csv.reader(inp, delimiter=';')
        for rows in reader:
            dict_from_csv = {rows[0].lower():rows[1] for rows in reader}
    return dict_from_csv
    
def write_dico_json(dico, filename):
    f = open(filename, "w")
    json.dump(dico, f)
    f.close()
    



if __name__ == '__main__':

    print("\nLaunching PowerShell Script to retrieve AD accounts and their descriptions")
    script_path = "./Get_Desc.ps1"
    info = run(script_path)
    if info.returncode != 0:
        print("An error occured: %s", info.stderr)
    else:
        print("\nloading and processing PowerShell results")
        dict_csv = load_description("./output/desc.csv")
        print("\nCreating hash file in './output/description_hashes.json' and plain text file in './output/description_plain.json'")
        dict_hashes, dict_plain = hashes_desc(dict_csv)
        write_dico_json(dict_hashes, "./output/description_hashes.json")
        write_dico_json(dict_plain, "./output/description_plain.json")
        print("\nDone!")
    