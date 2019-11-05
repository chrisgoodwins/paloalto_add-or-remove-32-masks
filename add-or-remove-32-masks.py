###############################################################################
#
# Script:       add-or-remove-32-masks.py
#
# Author:       Chris Goodwin <cgoodwin@paloaltonetworks.com>
#
# Description:  Standardize /32 subnet masks across all host IP address objects
#               for a Palo Alto Networks firewall or Panorama device group. Run
#               the script against a live device, or against at config file.
#
# Requirements: requests
#
# Python:       Version 2
#
###############################################################################
###############################################################################


import getpass
import sys
import os
import re
import time
from xml.etree import ElementTree as ET
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError('requests support not available, please install module')

###############################################################################
###############################################################################


# Prompts the user to enter the IP/FQDN of a firewall to retrieve the api key
def getfwipfqdn():
    while True:
        try:
            fwipraw = raw_input("\nPlease enter Panorama/firewall IP or FQDN: ")
            ipr = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", fwipraw)
            fqdnr = re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", fwipraw)
            if ipr:
                break
            elif fqdnr:
                break
            else:
                print("\nThere was something wrong with your entry. Please try again...\n")
        except:
            print("\nThere was some kind of problem entering your IP or FQDN. Please try again...\n")
    return fwipraw


# Prompts the user to enter their username to retrieve the api key
def getuname():
    while True:
        try:
            username = raw_input("Please enter your user name: ")  # 3 - 24 characters {3,24}
            usernamer = re.match(r"^[a-zA-Z0-9_-]{3,24}$", username)
            if usernamer:
                break
            else:
                print("\nThere was something wrong with your entry. Please try again...\n")
        except:
            print("\nThere was some kind of problem entering your user name. Please try again...\n")
    return username


# Prompts the user to enter their password to retrieve the api key
def getpassword():
    while True:
        try:
            password = getpass.getpass("Please enter your password: ")
            passwordr = re.match(r"^.{5,50}$", password)  # simple validate PANOS has no password characterset restrictions
            if passwordr:
                break
            else:
                print("\nThere was something wrong with your entry. Please try again...\n")
        except:
            print("\nThere was some kind of problem entering your password. Please try again...\n")
    return password


# Retrieves the user's api key
def getkey(fwip):
    while True:
        try:
            fwipgetkey = fwip
            username = getuname()
            password = getpassword()
            keycall = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwipgetkey, username, password)
            r = requests.get(keycall, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == "success":
                apikey = tree[0][0].text
                break
            else:
                print("\nYou have entered an incorrect username or password. Please try again...\n")
        except requests.exceptions.ConnectionError:
            print("\nThere was a problem connecting to the firewall.  Please check the IP or FQDN and try again...\n")
            exit()
    return apikey


# Presents the user with a choice of device-groups
def getDG(fwip, mainkey, devTree):
    if devTree is None:
        dgXmlUrl = "https://%s/api/?type=config&action=get&xpath=/config/devices/entry/device-group&key=%s" % (fwip, mainkey)
        r = requests.get(dgXmlUrl, verify=False)
        devTree = ET.fromstring(r.text)
        devTreeString = './/device-group/entry'
    else:
        devTreeString = 'devices/entry/device-group/entry'
    dgList = []
    for entry in devTree.findall(devTreeString):
        dgList.append(entry.get('name'))
    while True:
        try:
            print('\n\nHere\'s a list of device groups found in Panorama...\n')
            i = 1
            for dgName in dgList:
                print('%s) %s' % (i, dgName))
                i += 1
            dgChoice = int(raw_input('\nChoose a number for the device-group:\n\nAnswer is: '))
            print('\n')
            time.sleep(1)
            reportDG = dgList[dgChoice - 1]
            break
        except:
            print("\n\nThat's not a number in the list, try again...\n")
            time.sleep(1)
    return reportDG


# Determines whether the device is Panorama or firewall
def getDevType(fwip, mainkey, devTree):
    if devTree is None:
        devURL = "https://%s/api/?type=config&action=get&xpath=/config/devices/entry/device-group&key=%s" % (fwip, mainkey)
        r = requests.get(devURL, verify=False)
        devTree = ET.fromstring(r.text)
    if devTree.find('.//device-group/entry') is None:
        devType = 'fw'
        print('\n\n...Auto-detected device type to be a firewall...\n\n')
    else:
        devType = 'pano'
        print('\n\n...Auto-detected device type to be Panorama...\n\n')
    time.sleep(1)
    return devType


# Returns a list of address objects from firewall or Panorama DG
def getAddressObjects(fwip, mainkey, dg, devTree):
    if dg is None:
        if devTree is None:
            devURL = "https://%s/api/?type=config&action=get&xpath=/config/devices/entry/vsys/entry/address&key=%s" % (fwip, mainkey)
            r = requests.get(devURL, verify=False)
            devTree = ET.fromstring(r.text)
            addrList = devTree.findall('.//address/entry')
        else:
            addrList = devTree.findall('./devices/entry/vsys/entry/address/entry')
    else:
        if devTree is None:
            devURL = "https://%s/api/?type=config&action=get&xpath=/config/devices/entry/device-group/entry[@name='%s']/address&key=%s" % (fwip, dg, mainkey)
            r = requests.get(devURL, verify=False)
            devTree = ET.fromstring(r.text)
            addrList = devTree.findall('.//address/entry')
        else:
            addrList = devTree.findall("./devices/entry/device-group/entry[@name='%s']/address/entry" % (dg))
    return addrList


# Pushes the API call to firewall or Panorama
def pushAddrChanges(fwip, mainkey, dg, devTree, newAddrObjString):
    if devTree is None:
        raw_input('\n\nPress Enter to push API calls to Panorama/firewall (or CTRL+C to kill the script)... ')
        if dg is None:
            devURL = "https://%s/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry/address&element=%s&key=%s" % (fwip, newAddrObjString, mainkey)
        else:
            devURL = "https://%s/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name='%s']/address&element=%s&key=%s" % (fwip, dg, newAddrObjString, mainkey)
        r = requests.get(devURL, verify=False)
        tree = ET.fromstring(r.text)
        status = tree.get('status')
    else:
        raw_input('\n\nPress Enter to push changes to Panorama/firewall config (or CTRL+C to kill the script)... ')
        time.sleep(1)
        status = 'success'
        devURL = None
    return status, devURL


# Removes /32 from hosts addr objects if they exist, prints them to screen, returns status and API call
def remove32s(fwip, mainkey, dg, devTree):
    addrList = getAddressObjects(fwip, mainkey, dg, devTree)
    newAddrObjString = ''
    print('\n\nThe following host address objects containing /32 subnet mask were found:\n')
    for entry in addrList:
        if entry.find('ip-netmask') is not None and '/32' in entry.find('ip-netmask').text:
            print(entry.get('name') + ': ' + entry.find('ip-netmask').text)
            entry.find('ip-netmask').text = entry.find('ip-netmask').text[:-3]
            newAddrObjString = newAddrObjString + ET.tostring(entry)
    if newAddrObjString == '':
        time.sleep(1)
        print('\n\nThere are no address objects fitting your criteria...\n\n')
        time.sleep(1)
        status = 'fail'
    else:
        status, devURL = pushAddrChanges(fwip, mainkey, dg, devTree, newAddrObjString)
    return status, devTree


# Adds /32 to host addr objects if they don't exist, prints them to screen, returns status and API call
def add32s(fwip, mainkey, dg, devTree):
    addrList = getAddressObjects(fwip, mainkey, dg, devTree)
    newAddrObjString = ''
    print('\n\nThe following host address objects without /32 subnet mask were found:\n')
    for entry in addrList:
        if entry.find('ip-netmask') is not None and '/' not in entry.find('ip-netmask').text:
            print(entry.get('name') + ': ' + entry.find('ip-netmask').text)
            entry.find('ip-netmask').text = entry.find('ip-netmask').text + '/32'
            newAddrObjString = newAddrObjString + ET.tostring(entry)
    if newAddrObjString == '':
        time.sleep(1)
        print('\n\nThere are no address objects fitting your criteria...\n\n')
        time.sleep(1)
        status = 'fail'
    else:
        status, devURL = pushAddrChanges(fwip, mainkey, dg, devTree, newAddrObjString)
    return status, devTree


# Presents the user with the option to add or remove /32 subnet masks
def addRemoveChoice(fwip, mainkey, dg, devTree):
    while True:
        userChoice = raw_input('\n\nWould you like to add or remove /32 subnet masks?\n\n1) Add /32 subnet masks\n2) Remove /32 subnet masks\n\nAnswer: ')
        if userChoice == '1':
            status, result = add32s(fwip, mainkey, dg, devTree)
            break
        elif userChoice == '2':
            status, result = remove32s(fwip, mainkey, dg, devTree)
            break
        else:
            print("\n\nChoose '1' or '2', try again...\n")
            time.sleep(1)
    return status, result


# Checks the status from the changes that were made from API call or config change
def checkStatus(devTree, status, result):
    if status == 'success':
        if devTree is None:
            print('\n\nYour changes were successfully pushed to your PAN device')
        else:
            print('\n\nYour changes were successfully written to config')
    elif status == 'fail':
        return status
    else:
        print('\n\nSomething went wrong while pushing your config to the firewall/Panorama\n\n')
        print('Here is the faulty API call:\n\n' + result)
        exit()


def main():
    fwip = None
    mainkey = None
    devTree = None
    dg = None
    successCheck = None
    path = ''
    if len(sys.argv) < 2:
        fwip = getfwipfqdn()
        mainkey = getkey(fwip)
    else:
        file = sys.argv[1]
        panConfig = ET.parse(file)
        if '/' or '\\' in file:
            path, file = os.path.split(file)
        devTree = panConfig.getroot()
        print('\n\n\n...Device config loaded from command argument...')
    devType = getDevType(fwip, mainkey, devTree)
    run = True
    while run is True:
        if devType == 'pano':
            dg = getDG(fwip, mainkey, devTree)
            status, result = addRemoveChoice(fwip, mainkey, dg, devTree)
            if status == 'success':
                successCheck = True
            checkStatus(devTree, status, result)
            while True:
                dgChoice = raw_input('\n\nWould you like to run this script against another device group? [Y/n]  ')
                if dgChoice == '' or dgChoice == 'Y' or dgChoice == 'y':
                    break
                elif dgChoice == 'N' or dgChoice == 'n':
                    run = False
                    break
                else:
                    print("\n\nChoose '1' or '2', try again...\n")
                    time.sleep(1)
        else:
            status, result = addRemoveChoice(fwip, mainkey, dg, devTree)
            if checkStatus(devTree, status, result) == 'fail':
                continue
            else:
                successCheck = True
                run = False
    if devTree is not None and successCheck is True:
        print('\nWriting config to file. Please hold....\n')
        panConfig.write(os.path.join(path, 'EDITED_BY_SCRIPT_' + file))
        print('\n\n\nYour config was saved as EDITED_BY_SCRIPT_' + file)
    print('\n\n\nHave a great day!!\n\n')


if __name__ == '__main__':
    main()
