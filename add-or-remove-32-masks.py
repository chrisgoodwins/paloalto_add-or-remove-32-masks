
import getpass
import sys
import re
import time
from xml.etree import ElementTree as ET
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError('requests support not available, please install module')
############################################################################
############################################################################


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
    dgList = []
    for entry in devTree.findall('.//device-group/entry'):
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
        else:
            addrList = devTree.findall('.//address/entry')
    else:
        if devTree is None:
            devURL = "https://%s/api/?type=config&action=get&xpath=/config/devices/entry/device-group/entry[@name='%s']/address&key=%s" % (fwip, dg, mainkey)
            r = requests.get(devURL, verify=False)
            devTree = ET.fromstring(r.text)
        else:
            addrList = devTree.findall(".//device-group/entry[@name='%s']/address/entry" % (dg))
    return addrList


# Pushes the API call to firewall or Panorama
def pushApiCall(fwip, mainkey, dg, newAddrObjString):
    raw_input('\nPress Enter to push API calls to Panorama/firewall (or CTRL+C to kill the script)... ')
    if dg is None:
        devURL = "https://%s/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry/address&element=%s&key=%s" % (fwip, newAddrObjString, mainkey)
    else:
        devURL = "https://%s/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name='%s']/address&element=%s&key=%s" % (fwip, dg, newAddrObjString, mainkey)
    r = requests.get(devURL, verify=False)
    tree = ET.fromstring(r.text)
    status = tree.get('status')
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
        print('\n\nThere are no address objects fitting your criteria...\n\nGoodbye!!!\n\n\n')
        exit()
    if devTree is None:
        status, devURL = pushApiCall(fwip, mainkey, dg, newAddrObjString)
    else:
        status = 'success'
        devTree = None
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
        print('\n\nThere are no address objects fitting your criteria...\n\nGoodbye!!!\n\n\n')
        exit()
    if devTree is None:
        status, devURL = pushApiCall(fwip, mainkey, dg, newAddrObjString)
    else:
        status = 'success'
        devTree = None
    return status, devTree


def main():
    fwip = None
    mainkey = None
    devTree = None
    dg = None
    if len(sys.argv) < 2:
        fwip = getfwipfqdn()
        mainkey = getkey(fwip)
    else:
        panConfig = ET.parse(sys.argv[1])
        devTree = panConfig.getroot()
        print('\n\n\n...Device config loaded from command argument...')
    devType = getDevType(fwip, mainkey, devTree)
    if devType == 'pano':
        dg = getDG(fwip, mainkey, devTree)
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
    if status == "success":
        if devTree is None:
            print('\n\nYour changes were successfully pushed to your PAN device\n\n\nHave a great day!!\n\n')
        else:
            raw_input('\nPress Enter to push changes to Panorama/firewall config (or CTRL+C to kill the script)... ')
            panConfig.write('EDITED_BY_SCRIPT_' + sys.argv[1])
            print('\n\nYour changes were successfully made, and your config was saved as EDITED_BY_SCRIPT_' + sys.argv[1])
    else:
        print('\n\nSomething went wrong while pushing your config to the firewall\n\n')
        print('Here is the faulty API call:\n\n' + result)


if __name__ == '__main__':
    main()