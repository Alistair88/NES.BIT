# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# ### Quickstart: Azure Key Vault client library for Python
#
# [azure-keyvault-secrets 4.0.1](https://pypi.org/project/azure-keyvault-secrets/)

# Example from above website

# Notes are in ResourceStatusNotes.md

import os
#import cmd
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.datafactory import DataFactoryManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.datafactory.models import *
import adal
import requests
import json
#import jsonpath
import pandas as pd
from dateutil import parser as pr
from datetime import datetime, timedelta
import time

# Monitor the pipeline run
rg_name = 'ARBResourceGroup'
df_name = 'DataFactoryTutorialARB'
run_id = '9bab98ce-cfff-4603-9a41-9a71dc1e3b7d'

keyVaultName = os.environ["KEY_VAULT_NAME"]
KVUri = "https://" + keyVaultName + ".vault.azure.net"

credential = DefaultAzureCredential()
client = SecretClient(vault_url=KVUri, credential=credential)

REGION = 'westeurope'
GROUP_NAME = 'ARBResourceGroup'
SERVER_NAME = 'mysqlserverarb'
DATABASE_NAME = 'mySampleDatabase'

client_id = client.get_secret("clientId").value
client_secret = client.get_secret("clientSecret").value
tenant_id = client.get_secret("tenantId").value
authority_url = 'https://login.microsoftonline.com/' + tenant_id

subscription_id = os.environ['subscription_Id']
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


def print_dataframe(dfName):
    df = pd.DataFrame(dfName)
    print(df)


def print_activity_run_details(activity_run):
    """Print activity run details."""
    print("\n\tActivity run details\n")
    print("\tActivity run status: {}".format(activity_run.status))
    if activity_run.status == 'Succeeded':
        print("\tPipeline name: {}".format(activity_run.pipeline_name))
        print("\tActivity name: {}".format(activity_run.activity_name))
        print("\tNumber of bytes read: {}".format(
            activity_run.output['dataRead']))
        print("\tNumber of bytes written: {}".format(
            activity_run.output['dataWritten']))
        print("\tCopy duration: {}".format(
            activity_run.output['copyDuration']))
        print("\tStart time : {}".format(activity_run.activity_run_start))
        print("\tEndtime : {}".format(activity_run.activity_run_end))

    else:
        print("\tErrors: {}".format(activity_run.error['message']))


def DataFactoryStatus():
    '''
    Connect to Azure and list data factories in a resource group.
    '''
    params = {'api-version': '2018-06-01'}
    url = resource + '/subscriptions/' + subscription_id + \
        '/resourceGroups/' + GROUP_NAME + '/providers/Microsoft.DataFactory/factories'
    r = requests.get(url, headers=headers, params=params)
    df_list = []
    # print(json.dumps(r.json(), indent=4, separators=(',', ': ')))
    print("\nData factory status")
    data = json.loads(json.dumps(r.json()))
    for p in data['value']:
        df_list.append(
            {"Name": p['name'], "state": p['properties']['provisioningState']})
    print_dataframe(df_list)


def pipelineInfo():

    df_name = 'DataFactoryTutorialARB'

    fmt = '%d/%m/%Y %H:%M'
    url = 'https://management.azure.com/subscriptions/' + subscription_id + '/resourceGroups/' + GROUP_NAME + \
        '/providers/Microsoft.DataFactory/factories/' + \
        df_name + '/queryPipelineRuns?api-version=2018-06-01'

    r = requests.post(url, headers=headers)
    #print(json.dumps(r.json(), indent=4, separators=(',', ': ')))

    print("{:<25} {:<20} {:<20} {:<15} {:<20} {:<10}".format(
        "pipelineName", "runStart", "runEnd", "status", "lastUpdated", "isLatest"))
    data = json.loads(json.dumps(r.json()))
    for item in data['value']:
        print('{0:<25} {1:<20} {2:<20} {3:<15} {4:<20} {5:<10}'.format(item['pipelineName'], pr.parse(item['runStart']).strftime(
            fmt), pr.parse(item['runEnd']).strftime(fmt), item['status'], pr.parse(item['lastUpdated']).strftime(fmt), item['isLatest']))
        print('')


def pipelineRuns():
    adf_client = DataFactoryManagementClient(credentials, subscription_id)
    # time.sleep(30)
    pipeline_run = adf_client.pipeline_runs.get(rg_name, df_name, run_id)
    print("\n\tPipeline run status: {}".format(pipeline_run.status))
    filter_params = RunFilterParameters(
        last_updated_after=datetime.now() - timedelta(7), last_updated_before=datetime.now() + timedelta(1))
    query_response = adf_client.activity_runs.query_by_pipeline_run(
        rg_name, df_name, run_id, filter_params)
    print_activity_run_details(query_response.value[0])


if __name__ == "__main__":
    DataFactoryStatus()
    pipelineInfo()
    pipelineRuns()
