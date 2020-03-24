import requests
import csv
from collections import namedtuple

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


if __name__ == "__main__":
    get_product_cves()
