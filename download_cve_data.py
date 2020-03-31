from airflow import DAG
from airflow.operators.python_operator import PythonOperator
import requests
import csv
from collections import namedtuple
from datetime import datetime, timedelta
import os
import sys
import uuid
from azure.storage.blob import BlockBlobService, PublicAccess
from airflow.hooks.base_hook import BaseHook
import logging

def get_cve_json(vendor, product):
    r = requests.get(f'http://cve.circl.lu/api/search/{vendor}/{product}')
    return r.json()


def combine_cve_results(cve_jsons):
    all_cves = []
    for json in cve_jsons:
        for result in json["results"]:
            all_cves.append([result["id"], result["cvss"], result["summary"], result["Modified"]])
    return all_cves


def cve_data_to_csv(cve_data, filename="cve_data.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE ID", "CVSS", "Vulnerability Summary", "Last updated"])
        writer.writerows(cve_data)


def get_product_cves():
    Product = namedtuple('Product', ['vendor', 'name'])
    all_products = [Product("microsoft", "outlook"), Product("microsoft", "skype_for_business")]
    cve_results = []
    for product in all_products:
        cve_results.append(get_cve_json(product.vendor, product.name))
    combined_results = combine_cve_results(cve_results)
    cve_data_to_csv(combined_results)


def csv_upload_to_blob():
    try:
        connection = BaseHook.get_connection("psoe_blue_sky")
        # Access Storage Account
        block_blob_service = BlockBlobService(account_name=connection.login, account_key=connection.password)
        # Create Container
        container_name = "thevuncsvblob"
        block_blob_service.create_container(container_name)
        block_blob_service.set_container_acl(container_name, public_access=PublicAccess.Container)

        # Get CSV File
        local_path = os.path.abspath(os.path.join(os.path.curdir, os.pardir))
        local_file_name = "cve_data.csv"
        full_path_to_file = os.path.join(local_path, local_file_name)

        # Upload file
        logging.error("Got file: " + full_path_to_file)
        logging.error("\nUploading to Blob storage as " + local_file_name)
        block_blob_service.create_blob_from_path(container_name, local_file_name, full_path_to_file)

    except Exception as e:
        logging.error(e)


with DAG('export_cve_data', description='Export CVE data', schedule_interval='@once', start_date=datetime.now() - timedelta(hours=24)) as dag:
    export_task = PythonOperator(task_id='export_task', python_callable=get_product_cves)

export_task
