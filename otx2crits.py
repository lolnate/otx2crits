import argparse
import datetime
import json
import os
import requests
import sys

from pycrits import pycrits
from configparser import ConfigParser

# Crits vocabulary
from vocabulary.indicators import IndicatorTypes as it

def parse_config(location):
    try:
        config = ConfigParser()
        config.read(location)
    except Exception as e:
        print('Error parsing config: {}'.format(e))
        return False
    if len(config.sections()) == 0:
        print('Configuration file not found: {}'.format(location))
        return False
    return config


def load_config(given_location=None):
    '''
    This checks several locations for the config file if a location is not
    provided.
    1) OTX_CONFIG_FILE environment variable
    2) ~/.otx_config
    '''
    # given_location
    if given_location:
        return parse_config(given_location)
    # environment variable
    CONFIG_FILE = os.environ.get('OTX_CONFIG_FILE', None)
    if CONFIG_FILE:
        return parse_config(CONFIG_FILE)
    # Final attempt
    CONFIG_FILE = os.path.join(os.path.expanduser('~'), '.otx_config')
    return parse_config(CONFIG_FILE)


def get_indicator_mapping():
    # Indicators with no matching type return None
    mapping = {
        'FileHash-SHA256' : it.SHA256,
        'FileHash-SHA1' : it.SHA1,
        'URI' : it.URI,
        'URL' : it.URI,
        'hostname' : it.DOMAIN,
        'domain' : it.DOMAIN,
        'IPv4' : it.IPV4_ADDRESS,
        'IPv6' : it.IPV6_ADDRESS,
        'email' : it.EMAIL_ADDRESS,
        'filepath' : it.FILE_PATH,
        'FileHash-MD5' : it.MD5,
        'Imphash' : it.IMPHASH,
        'PEhash' : None,
        'CIDR' : it.IPV4_SUBNET,
        'mutex' : it.MUTEX,
        'CVE' : None,
    }
    return mapping


def send_otx_get(url, otx_api_key, proxies=None, verify=True):
    headers = {
        'X-OTX-API-KEY' : otx_api_key,
    }

    r = requests.get(url, headers=headers, proxies=proxies, verify=verify)
    if r.status_code == 200:
        return r.text
    else:
        print('Error retrieving AlienVault OTX data')
        print('Status code was: {}'.format(r.status_code))
        return False


def get_subscribed_pulses(otx_url, otx_api_key, modified_since=None,
                          proxies=None, verify=True):
    args_append = ''
    if modified_since:
        args_append = '?modified_since={}'.format(modified_since.strftime(
            '%Y-%m-%d %H:%M:%S.%f'))

    response_data = send_otx_get('{}/pulses/subscribed{}'.format(otx_url,
                                                                 args_append),
                                 otx_api_key, proxies=proxies, verify=verify)
    if response_data:
        return json.loads(response_data)
    else:
        print("Error retrieving pulses. Exiting...")
        sys.exit(0)


def get_pulse_data(pulse_id, otx_url, otx_api_key, proxies=None, verify=True):
    response_data = send_otx_get('{}/pulses/{}'.format(otx_url, pulse_id),
                                 otx_api_key, proxies=proxies, verify=verify)
    if response_data:
        return json.loads(response_data)
    else:
        print('Error retrieving pulse with id {}'.format(pulse_id))
        return False


def is_pulse_in_crits(crits, pulse_id):
    result = crits.event_count( params={ 'c-tickets.ticket_number' : pulse_id } )
    if result > 0:
        return True
    return False


def build_crits_event(crits, event_title, description, crits_source,
                      params={}):
    event = crits.add_event('Intel Sharing', event_title, description,
                            crits_source, params=params)
    return event


def add_crits_indicator(crits, indicator_value, indicator_type, crits_source,
                        params={}):
    result = crits.add_indicator(indicator_type, indicator_value, crits_source,
                        params=params)
    if result:
        if result['return_code'] == 0:
            return result
        else:
            print('Error when adding CRITs Indicator: '
                  '{}'.format(result['message']))
    return False


def add_ticket_to_crits_event(crits_url, event_id, pulse_id, params={},
                              proxies={}, verify=True):
    '''
    Adds a ticket to the provided CRITs Event
    '''
    submit_url = '{}/api/v1/{}/{}/'.format(crits_url, 'events', event_id)
    headers = {
        'Content-Type' : 'application/json',
    }

    # date must be in the format %Y-%m-%d %H:%M:%S.%f
    formatted_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    data = {
        'action' : 'ticket_add',
        'ticket' : {
            'ticket_number' : pulse_id,
            'date' : formatted_date,
        }
    }

    r = requests.patch(submit_url, headers=headers, proxies=proxies,
                       params=params, data=json.dumps(data), verify=False)
    if r.status_code == 200:
        print('Ticket added successfully: {0} <-> {1}'.format(event_id,
                                                              pulse_id))
        return True
    else:
        print('Error with status code {0} and message {1} when adding a '
              'ticket to event: {2} <-> {3}'.format(r.status_code, r.text,
                                                    event_id, pulse_id))
    return False


def build_crits_relationship(crits_url, event_id, indicator_id, params={},
                             proxies={}, verify=True):
    '''
    Builds a relationship between the given event and indicator IDs
    '''
    submit_url = '{}/api/v1/{}/{}/'.format(crits_url, 'events', event_id)
    headers = {
        'Content-Type' : 'application/json',
    }

    data = {
        'action' : 'forge_relationship',
        'right_type' : 'Indicator',
        'right_id' : indicator_id,
        'rel_type' : 'Related To',
        'rel_date' : datetime.datetime.now(),
        'rel_confidence' : 'high',
        'rel_reason' : 'Related during automatic OTX import'
    }

    r = requests.patch(submit_url, proxies=proxies, params=params, data=data, verify=False)
    if r.status_code == 200:
        print('Relationship built successfully: {0} <-> '
              '{1}'.format(event_id,indicator_id))
        return True
    else:
        print('Error with status code {0} and message {1} between these '
              'indicators: {2} <-> {3}'.format(r.status_code, r.text,
                                               event_id, indicator_id))
        return False


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--dev', dest='dev', action='store_true',
                           default=False, help='Use your dev instance of '
                           'CRITS. For science.')
    argparser.add_argument('-c', dest='config', default=None, help='Provide '
                           'a specific configuration file path.')
    argparser.add_argument('-d', dest='days', default=None, type=int,
                           help='Specify the maximum age of a pulse in the '
                           'number of days.')
    args = argparser.parse_args()

    # Load the configuration
    config = load_config(args.config)
    # Now we're talkin
    otx_api_key = config.get('otx', 'otx_api_key')
    otx_url = config.get('otx', 'otx_url')

    proxies = {
            'http' : config.get('proxy', 'http'),
            'http' : config.get('proxy', 'https'),
    }

    crits_url = config.get('crits', 'prod_url')
    crits_dev_url = config.get('crits', 'dev_url')
    crits_username = config.get('crits', 'username')
    crits_api_key = config.get('crits', 'prod_api_key')
    crits_dev_api_key = config.get('crits', 'dev_api_key')
    crits_verify = config.getboolean('crits', 'verify')
    crits_source = config.get('crits', 'source')
    if args.dev:
        crits_url = crits_dev_url
        crits_api_key = crits_dev_api_key
    if crits_url[-1] == '/':
        crits_url = crits_url[:-1]

    modified_since = None
    if args.days:
        print('Searching for pulses modified in the last {} '
              'days'.format(args.days))
        modified_since = datetime.datetime.now()\
            - datetime.timedelta(days=args.days)

    # Get pycrits ready for magic
    crits = pycrits(crits_url, crits_username, crits_api_key, proxies=proxies,
                    verify=crits_verify)

    # Get our subscribed OTX pulses
    pulse_data = get_subscribed_pulses(otx_url, otx_api_key,
                                       modified_since=modified_since,
                                       proxies=proxies)

    # Now iterate through these pulses
    for pulse in pulse_data['results']:
        # This will be used to track relationships
        relationship_map = []

        print('Found pulse with id {} and title {}'.format(pulse['id'],
                                                           pulse['name']))
        if is_pulse_in_crits(crits, pulse['id']):
            print('Pulse was already in CRITs')
            continue

        print('Adding pulse {} to CRITs.'.format(pulse['name']))
        # Get the actual indicator and event data from the pulse
        indicator_data = get_pulse_data(pulse['id'], otx_url, otx_api_key,
                                        proxies=proxies)
        event_title = indicator_data['name']
        created = indicator_data['created']
        indicator_data['indicators'][0]
        reference = indicator_data['references'][0]
        description = indicator_data['description']
        bucket_list = indicator_data['tags']

        # Create the CRITs event first
        print('Adding Event to CRITs with title {}'.format(event_title))
        params = {
            'bucket_list' : bucket_list,
            'description' : description,
        }
        event = build_crits_event(crits, event_title, description,
                                  crits_source, params=params)
        event_id = event['id']

        # Add the indicators to CRITs
        mapping = get_indicator_mapping()
        if 'indicators' in indicator_data:
            for i in indicator_data['indicators']:
                # Reuse the params from creating the event
                _type = mapping[i['type']]
                if _type == None:
                    continue
                result = add_crits_indicator(crits, i['indicator'],
                                             mapping[i['type']], crits_source,
                                             params=params)
                if result:
                    print('Indicator created: {}'.format(result))
                    indicator_id = result['id']
                    print('Indicator created with id: '
                          '{}'.format(indicator_id))
                    relationship_map.append( indicator_id )

        # Add a ticket to the Event to track the pulse_id
        print('Adding ticket to Event {}'.format(event_title))
        params = {
            'api_key' : crits_api_key,
            'username' : crits_username,
        }
        success = add_ticket_to_crits_event(crits_url, event_id, pulse['id'],
                                            params=params, 
                                            proxies=proxies,
                                            verify=crits_verify)
        if not success:
            print('Forging on after a ticket error.')

        # Build the relationships between the event and indicators
        print('Building relationships.')
        for _id in relationship_map:
            build_crits_relationship(crits_url, event_id, _id, params=params,
                                     proxies=proxies, verify=crits_verify)


if __name__ == '__main__':
    main()
