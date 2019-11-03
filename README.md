# paloalto_add-or-remove-32-masks
Standardize subnet masks across all host IP address objects for a Palo Alto Networks firewall or Panorama device group

## Features
- Auto-detects device type, presents user with choice of device group if Panorama
- Searches all firewall or Panorama device group address objects, presents the user with the option to add or remove /32 subnet masks for all host ip-netmask address objects 
- Connect to firewall/Panorama via API or pass the xml config file as a command argument to work on offline config
