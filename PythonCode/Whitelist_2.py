import argparse
# import json
import os
# import re
import socket

import adal
import numpy as np
import pandas as pd
import requests
from azure.common.credentials import ServicePrincipalCredentials
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
# from azure.mgmt.compute import ComputeManagementClient
# from azure.mgmt.datafactory import DataFactoryManagementClient
# from azure.mgmt.datafactory.models import RunFilterParameters
# from azure.mgmt.resource import ResourceManagementClient
from lxml import etree as ET
from requests.exceptions import HTTPError

# import time
# from datetime import datetime, timedelta, timezone


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


def valid_ip(address):
    """
    Test the ip address to ensure that it is valid.

    Args: IP address

    Returns: True or False depending on the result.
    """
    try:
        socket.inet_aton(address)
        return True
    except:
        return False


def get_user_input():
    """
    Gets input from the user and then calls a function depending on the command line arguments provided.

    Args: none.

    Returns: nothing
    """

    parser = argparse.ArgumentParser(
        description="List a user's IP address or a range of addresses.  Whitelists or updates the address using the information provided ")

    subparsers = parser.add_subparsers()
    parser_list_rules_by_server = subparsers.add_parser('list_rules_by_server')
    parser_list_rules_by_server.add_argument(
        'rg_name', help="The name of the resource group")
    parser_list_rules_by_server.add_argument(
        'server_name', help="the name of the server")
    parser_list_rules_by_server.set_defaults(func=list_rules_by_server)

    parser_get_fw_rule = subparsers.add_parser('get_fw_rule')
    parser_get_fw_rule.add_argument(
        'rg_name', help="The name of the resource group")
    parser_get_fw_rule.add_argument(
        'server_name', help="the name of the server")
    parser_get_fw_rule.add_argument(
        "fw_rule", help="the name of the firewall rule")
    parser_get_fw_rule.set_defaults(func=get_fw_rule)

    parser_create_or_update_rule = subparsers.add_parser(
        'create_or_update_rule')
    parser_create_or_update_rule.add_argument(
        'rg_name', help="The name of the resource group", default='ARBResourceGroup')
    parser_create_or_update_rule.add_argument(
        'server_name', help="the name of the server", default='sqlserverarb')
    parser_create_or_update_rule.add_argument(
        "fw_rule", help="the name of the firewall rule")
    parser_create_or_update_rule.add_argument(
        "startIpAddress",  help="the first IP address in the range")
    parser_create_or_update_rule.add_argument(
        "endIpAddress",  help="the last IP address in the range")
    parser_create_or_update_rule.set_defaults(func=create_or_update_rule)

    args = parser.parse_args()
    args.func(args)


def list_rules_by_server(args):
    # Firewall rules - list by server
    """
    Lists the firewall rules for the given server in a given resource group. 

    Args: Resource group name and server name.

    Returns: None
    """
    # subscription_id = subscription_id

    params = {'api-version': '2014-04-01'}
    url = 'https://management.azure.com/subscriptions/' + subscription_id + '/resourceGroups/' + \
        args.rg_name + '/providers/Microsoft.Sql/servers/' + \
        args.server_name + '/firewallRules?'
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
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')
    else:
        print('Success!')


def get_fw_rule(args):
    # Firewall rules - list by server
    """
    Lists the firewall rule for the given firewall rule name.

    Args: Resource group name, server name and firewall nule name

    Returns: None
    """
    # rg_name = ''
    # server_name = ''
    params = {'api-version': '2014-04-01'}
    url = 'https://management.azure.com/subscriptions/' + subscription_id + '/resourceGroups/' + \
        args.rg_name + '/providers/Microsoft.Sql/servers/' + \
        args.server_name + '/firewallRules/' + args.fw_rule + '?'
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


def create_or_update_rule(args):
    """
    Creates or updates a firewall rule for the given firewall rule name, startIpAddress, and endIpAddress.

    Args: Resource group name, server name and firewall nule name

    Returns: None
    """
    if valid_ip(args.startIpAddress) and valid_ip(args.endIpAddress):
        body = {
            "properties": {
                "startIpAddress": args.startIpAddress,
                "endIpAddress": args.endIpAddress
            }
        }
        print("Firewall rule is {}, start ip address is {} and end ip address is {}".format(
            args.fw_rule, args.startIpAddress, args.endIpAddress))
        params = {'api-version': '2014-04-01'}

        url = 'https://management.azure.com/subscriptions/' + subscription_id + '/resourceGroups/' + \
            args.rg_name + '/providers/Microsoft.Sql/servers/' + \
            args.server_name + '/firewallRules/' + args.fw_rule + '?'

        requests.put(url, headers=headers, params=params, json=body)
    else:
        print("Incorrect IP address.  Please check!")


if __name__ == "__main__":
    get_user_input()
