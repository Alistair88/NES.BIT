import argparse
import json
import os
import re
import socket
import time
from datetime import datetime, timedelta, timezone

import adal
import numpy as np
import pandas as pd
import requests
from azure.common.credentials import ServicePrincipalCredentials
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.datafactory import DataFactoryManagementClient
from azure.mgmt.datafactory.models import RunFilterParameters
from azure.mgmt.resource import ResourceManagementClient
from dateutil import parser as pr
from requests.exceptions import HTTPError
from lxml import etree as ET

subscription_id = os.environ['subscription_Id']
keyVaultName = os.environ["KEY_VAULT_NAME"]
KVUri = "https://" + keyVaultName + ".vault.azure.net"

credential = DefaultAzureCredential()
client = SecretClient(vault_url=KVUri, credential=credential)

# Connect to Azure

client_id = client.get_secret("clientId").value
client_secret = client.get_secret("clientSecret").value
tenant_id = client.get_secret("tenantId").value
authority_url = 'https://login.microsoftonline.com/' + tenant_id

# os.environ['SUBSCRIPTION']
subscription_id = "79356184-2e28-4682-86c6-912f8b6856a0"
# Azure Resource Manager provider APIs URI.
resource = 'https://management.azure.com/'
context = adal.AuthenticationContext(authority_url)
token = context.acquire_token_with_client_credentials(
    resource, client_id, client_secret)
headers = {'Authorization': 'Bearer ' +
           token['accessToken'], 'Content-Type': 'application/json'}

credentials = ServicePrincipalCredentials(
    client_id=client_id,
    secret=client_secret,
    tenant=tenant_id
)

rg_name = 'ARBResourceGroup'
server_name = 'sqlserverarb'


def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False


def get_user_input():
    """
    Gets input from the user.
    """

    fw_rule = ''
    ipAddress = ''
    parser = argparse.ArgumentParser(
        description="Whitelist a user's IP address")
    parser.add_argument("fw_rule", help="the name of the firewall rule")
    parser.add_argument("ipAddress",  help="the user's IP address")
    args = parser.parse_args()
    # if (args.fw_rule == 1):
    # print("Rule name {}".format(args.fw_rule))
    # else:
    #     print("incorrect argument list.  Please re-enter")
    if valid_ip(args.ipAddress):
        # print("ipAddress {}".format(args.ipAddress))
        return args.fw_rule, args.ipAddress
    else:
        print("Incorrect IP address.  Please re-enter")
    # params = {'api-version': '2014-04-01'}
    # # fw_rule = 'ClientIp-2020-4-10_14-6-19'
    # url = 'https://management.azure.com/subscriptions/' + subscription_id + '/resourceGroups/' + \
    #     rg_name + '/providers/Microsoft.Sql/servers/' + \
    #     server_name + '/firewallRules/' + fw_rule + ''
    # # req = requests.put(url, headers=headers, params=params, json=body)
    # # print(req.text)
    # requests.put(url, headers=headers, params=params, json=body)

    return fw_rule, ipAddress


def list_fw_rules():
    # Firewall rules - list by server
    """
    Lists the firewall rules for the given server in a given resource group. 
    """
    params = {'api-version': '2014-04-01'}
    url = 'https://management.azure.com/subscriptions/' + subscription_id + '/resourceGroups/' + \
        rg_name + '/providers/Microsoft.Sql/servers/' + server_name + '/firewallRules?'
    try:
        response = requests.get(url, headers=headers, params=params, timeout=1)
        # print(response.text)
        root = ET.fromstring(response.content)
        rule_name = [name.text for name in root.iter(
            '{http://schemas.microsoft.com/ado/2007/08/dataservices}name')]

        startIpAddress = [startIpAddress.text for startIpAddress in root.iter(
            '{http://schemas.microsoft.com/ado/2007/08/dataservices}startIpAddress')]

        endIpAddress = [endIpAddress.text for endIpAddress in root.iter(
            '{http://schemas.microsoft.com/ado/2007/08/dataservices}endIpAddress')]

        zippedList = list(zip(rule_name, startIpAddress, endIpAddress))

        dfObj = pd.DataFrame(zippedList, columns=[
                             'Name', 'Start IpAddress', 'End IpAddress'])
        dfObj.index = np.arange(1, len(dfObj)+1)
        print(dfObj)
        # If the response was successful, no Exception will be raised
        response.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')  # Python 3.6
    except Exception as err:
        print(f'Other error occurred: {err}')  # Python 3.6
    else:
        print('Success!')


def create_update_rule():
    fw_rule = get_user_input()[0]
    startIpAddress = get_user_input()[1]
    endIpAddress = startIpAddress
    body = {
        "properties": {
            "startIpAddress": startIpAddress,
            "endIpAddress": endIpAddress
        }
    }
    print("Firewall rule is {}, start ip address is {} and end ip address is {}".format(
        fw_rule, startIpAddress, endIpAddress))
    params = {'api-version': '2014-04-01'}
    # fw_rule = 'ClientIp-2020-4-10_14-6-19'
    url = 'https://management.azure.com/subscriptions/' + subscription_id + '/resourceGroups/' + \
        rg_name + '/providers/Microsoft.Sql/servers/' + \
        server_name + '/firewallRules/' + fw_rule + ''
    #req = 
    requests.put(url, headers=headers, params=params, json=body)
    # print(req.text)


if __name__ == "__main__":
    # get_user_input()
    # list_fw_rules()
    create_update_rule()
