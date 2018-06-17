import requests
import tldextract
import whois
import argparse
import datetime


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
    with open(filepath, 'r') as file:
        url_lines = file.readlines()
        return url_lines


def is_server_respond_with_ok(url):
    try:
        response = requests.get(url)
    except(
        requests.exceptions.MissingSchema,
        requests.exceptions.ConnectionError
    ):
        return None
    return response.status_code == requests.codes.ok


def get_domain_expiration_date(url):
    url_parts = tldextract.extract(url)
    domain_name = '.'.join([url_parts.domain, url_parts.suffix])
    whois_dict = whois.whois(domain_name)
    expiration_date = whois_dict.expiration_date
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]
    return expiration_date


if __name__ == '__main__':
    args = get_args()
    current_date = datetime.datetime.now()
    url_lines = load_urls4check(args.filepath)
    for url_line in url_lines:
        url = url_line.replace('\n', '')
        if is_server_respond_with_ok(url):
            print('Site {} responding successfully'.format(url))
        else:
            print('Connection not established, or URL {} wrong!'.format(url))
        exp_date = get_domain_expiration_date(url)
        if not exp_date:
            print('Domain of {} is not registered!'.format(url))
            continue
        if (exp_date - current_date) > datetime.timedelta(days=30):
            print('Domain is registered for more than a month.'.format(url))
            continue
        exit("Domain will stop it's work less than a month!".format(url))
