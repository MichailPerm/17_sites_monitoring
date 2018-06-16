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
    with open(filepath, 'r') as f:
        urls = f.readlines()
        return urls


def is_server_respond_with_200(url):
    try:
        response = requests.get(url, allow_redirects=True)
    except(
        requests.exceptions.MissingSchema,
        requests.exceptions.ConnectionError
    ):
        return None
    if response.status_code == requests.codes.ok:
        return True
    else:
        return None


def get_domain_expiration_date(domain_name):
    whois_dict = whois.whois(domain_name)
    exp_date = whois_dict.expiration_date
    if isinstance(whois_dict.expiration_date, list):
        exp_date = whois_dict.expiration_date[0]
    return exp_date


if __name__ == '__main__':
    args = get_args()
    current_date = datetime.datetime.now()
    urls = load_urls4check(args.filepath)
    for url in urls:
        url = url.replace('\n', '')
        if is_server_respond_with_200(url):
            data_from_url = tldextract.extract(url)
            domain_name = '.'.join(
                [data_from_url.domain, data_from_url.suffix]
            )
            exp_date = get_domain_expiration_date(domain_name)
            if (exp_date - current_date) > datetime.timedelta(days=30):
                print('Site {} works correctly without a problem.'.format(url))
            else:
                print('Site {} will stop it\'s work less than a month!'.format(
                        url))

        else:
            print('Connection not established, or URL {} wrong!'.format(url))
