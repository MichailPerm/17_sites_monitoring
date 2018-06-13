import requests
import tldextract
import whois
import argparse


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f',
        '--filepath',
        help='Path to file with urls',
        required=True
    )
    return parser.parse_args()


def load_urls4check(filepath):
    with open(filepath, 'r') as f:
        urls = f.readlines()
        return urls

def is_server_respond_with_200(url):
    response = requests.get(url)
    if response.status_code == requests.codes.ok:
        return True
    else:
        return None

def get_domain_expiration_date(domain_name):
    domain_dict = whois.query(domain_name)
    return domain_dict.expiration_date

if __name__ == '__main__':
    args = get_args()
    urls = load_urls4check(args.filepath)
    for url in urls:
        if is_server_respond_with_200(url):
            extract_result = tldextract.extract(url)
            domain_name = '.'.join(
                [extract_result.domain, extract_result.suffix]
            )
            exp_date = get_domain_expiration_date(domain_name)
            print(exp_date)
