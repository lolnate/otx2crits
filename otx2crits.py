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

class OTX2CRITs(object):

    def __init__(self, dev=False, config=None, days=None):
        # Load the configuration
        self.config = self.load_config(config)

        # Now we're talkin
        self.otx_api_key = self.config.get('otx', 'otx_api_key')
        self.otx_url = self.config.get('otx', 'otx_url')

        self.proxies = {
            'http' : self.config.get('proxy', 'http'),
            'https' : self.config.get('proxy', 'https'),
        }

        self.crits_url = self.config.get('crits', 'prod_url')
        self.crits_dev_url = self.config.get('crits', 'dev_url')
        self.crits_username = self.config.get('crits', 'username')
        self.crits_api_key = self.config.get('crits', 'prod_api_key')
        self.crits_dev_api_key = self.config.get('crits', 'dev_api_key')
        self.crits_verify = self.config.getboolean('crits', 'verify')
        self.crits_source = self.config.get('crits', 'source')
        if dev:
            self.crits_url = self.crits_dev_url
            self.crits_api_key = self.crits_dev_api_key
        if self.crits_url[-1] == '/':
            self.crits_url = self.crits_url[:-1]

        self.crits_proxies = {
            'http' : self.config.get('crits', 'crits_proxy'),
            'https' : self.config.get('crits', 'crits_proxy'),
        }

        self.modified_since = None
        if days:
            print('Searching for pulses modified in the last {} '
                  'days'.format(days))
            self.modified_since = datetime.datetime.now()\
                - datetime.timedelta(days=days)

        # Get pycrits ready for magic
        self.crits = pycrits(self.crits_url, self.crits_username,
                             self.crits_api_key, proxies=self.crits_proxies,
                             verify=self.crits_verify)


    def execute(self):
        for pulse in self.get_pulse_generator(modified_since=\
                                              self.modified_since,
                                              proxies=self.proxies):

            # This will be used to track relationships
            relationship_map = []

            print('Found pulse with id {} and title {}'.format(pulse['id'],
                                                               pulse['name'].encode("utf-8")))
            if self.is_pulse_in_crits(pulse['id']):
                print('Pulse was already in CRITs')
                continue

            print('Adding pulse {} to CRITs.'.format(pulse['name'].encode("utf-8")))
            # Get the actual indicator and event data from the pulse
            indicator_data = pulse['indicators']
            event_title = pulse['name']
            created = pulse['created']
            reference =''
            if not reference:

                reference = 'No reference documented'
            else:
                reference = pulse['references'][0]

            description = pulse['description']
            bucket_list = pulse['tags']

            # CRITs requires a description
            if description == '':
                description = 'No description given.'

            # Create the CRITs event first
            print('Adding Event to CRITs with title {}'.format(event_title.encode("utf-8")))
            params = {
                'bucket_list' : ','.join(bucket_list),
                'description' : description,
                'reference' : reference,
                'method' : 'otx2crits',
            }
            event = self.build_crits_event(event_title, self.crits_source,
                                           description, params=params)
            if 'id' not in event:
                print('id not found in event object returned from crits!')
                print('Event object was: {}'.format(repr(event)))
                print('Skipping event: {}.'.format(event_title))
                continue
            event_id = event['id']

            # Add a ticket to the Event to track the pulse_id
            # This goes above the indicators because sometimes adding
            # indicators fails and we end up with many duplicate events.
            print('Adding ticket to Event {}'.format(event_title.encode("utf-8")))
            params = {
                'api_key' : self.crits_api_key,
                'username' : self.crits_username,
            }
            success = self.add_ticket_to_crits_event(event_id, pulse['id'],
                                                params=params,
                                                proxies=self.crits_proxies,
                                                verify=self.crits_verify)
            if not success:
                print('Forging on after a ticket error.')

            # Add the indicators to CRITs
            mapping = self.get_indicator_mapping()
            for i in indicator_data:
                # Reuse the params from creating the event
                if i['type'] in mapping:
                    _type = mapping[i['type']]
                else:
                    # We found an indicator with a type we don't support.
                    print("We don't support type {}".format(i['type']))
                    continue
                if _type == None:
                    continue
                result = self.add_crits_indicator(i['indicator'],
                                                  mapping[i['type']],
                                                  self.crits_source,
                                                  params=params)
                if result:
                    print('Indicator created: {}'.format(result))
                    indicator_id = result['id']
                    print('Indicator created with id: '
                          '{}'.format(indicator_id))
                    relationship_map.append( indicator_id )


            # Build the relationships between the event and indicators
            print('Building relationships.')
            for _id in relationship_map:
                self.build_crits_relationship(event_id, _id, params=params,
                                              proxies=self.crits_proxies,
                                              verify=self.crits_verify)


    def parse_config(self, location):
        '''
        Parses the otx config file from the given location. Attempts to find
        the config file if one is not given.
        '''
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


    def load_config(self, given_location=None):
        '''
        This checks several locations for the config file if a location is not
        provided.
        1) OTX_CONFIG_FILE environment variable
        2) ~/.otx_config
        '''
        # given_location
        if given_location:
            return self.parse_config(given_location)
        # environment variable
        CONFIG_FILE = os.environ.get('OTX_CONFIG_FILE', None)
        if CONFIG_FILE:
            return self.parse_config(CONFIG_FILE)
        # Final attempt
        CONFIG_FILE = os.path.join(os.path.expanduser('~'), '.otx_config')
        return self.parse_config(CONFIG_FILE)


    def get_indicator_mapping(self):
        # Indicators with no matching type return None
        mapping = {
            'FileHash-SHA256': it.SHA256,
            'FileHash-SHA1': it.SHA1,
            'URI': it.URI,
            'URL': it.URI,
            'hostname': it.DOMAIN,
            'domain': it.DOMAIN,
            'IPv4': it.IPV4_ADDRESS,
            'IPv6': it.IPV6_ADDRESS,
            'email': it.EMAIL_ADDRESS,
            'Email': it.EMAIL_ADDRESS,
            'filepath': it.FILE_PATH,
            'Filepath': it.FILE_PATH,
            'FilePath': it.FILE_PATH,
            'FileHash-MD5': it.MD5,
            'Imphash': it.IMPHASH,
            'PEhash': None,
            'CIDR': it.IPV4_SUBNET,
            'mutex': it.MUTEX,
            'Mutex': it.MUTEX,
            'CVE': None,
            'Yara': None,
        }
        return mapping


    def send_otx_get(self, url, proxies=None, verify=True):
        headers = {
            'X-OTX-API-KEY' : self.otx_api_key,
        }

        r = requests.get(url, headers=headers, proxies=proxies, verify=verify)
        if r.status_code == 200:
            return r.text
        else:
            print('Error retrieving AlienVault OTX data')
            print('Status code was: {}'.format(r.status_code))
            return False


    def get_pulse_generator(self, modified_since=None,
                              proxies=None, verify=True):
        '''
        This will yield a pulse and all its data while it can obtain more data.
        The OTX API has an issue when not specifying a "limit" on the pulses
        returned. If we specify a limit, we can get all of our pulses, but if
        we don't, the API will only ever return 5 pulses total. Derp.

        This also takes advantage of returning multiple pages of pulses, so
        a reasonable amount of data is returned at once.
        '''
        request_args = ''
        args = []
        page = 1
        if modified_since:
            args.append('modified_since={}'.format(\
                modified_since.strftime('%Y-%m-%d %H:%M:%S.%f')))

        args.append('limit=10')
        args.append('page=1')
        request_args = '&'.join(args)
        request_args = '?{}'.format(request_args)

        response_data = self.send_otx_get('{}/pulses/subscribed{}'\
                                          .format(self.otx_url, request_args),
                                            proxies=proxies, verify=verify)
        # We are going to loop through to get all the pulse data
        generator_data = []
        while response_data:
            all_pulses = json.loads(response_data)
            if 'results' in all_pulses:
                for pulse in all_pulses['results']:
                    yield pulse
            response_data = None
            if 'next' in all_pulses:
                if all_pulses['next']:
                    response_data = self.send_otx_get(all_pulses['next'],
                                                      proxies=proxies,
                                                      verify=verify)


    def get_pulse_data(self, pulse_id, proxies=None, verify=True):
        response_data = self.send_otx_get('{}/pulses/{}'.format(self.otx_url,
                                                                pulse_id),
                                     proxies=proxies, verify=verify)
        if response_data:
            return json.loads(response_data)
        else:
            print('Error retrieving pulse with id {}'.format(pulse_id))
            return False


    def is_pulse_in_crits(self, pulse_id):
        '''
        Checks to see if the given pulse_id is already in CRITs as a ticket
        in an Event object
        '''
        result = self.crits.event_count( params={ 'c-tickets.ticket_number' :
                                                 pulse_id } )
        if result > 0:
            return True
        return False


    def build_crits_event(self, event_title, crits_source, description='',
                          params={}):
        '''
        Builds an event in CRITs
        '''
        event = self.crits.add_event('Intel Sharing', event_title, description,
                                crits_source, params=params)
        return event


    def add_crits_indicator(self, indicator_value, indicator_type, crits_source,
                            params={}):
        result = self.crits.add_indicator(indicator_type, indicator_value,
                                          crits_source, params=params)
        if result:
            if result['return_code'] == 0:
                return result
            else:
                print('Error when adding CRITs Indicator: '
                      '{}'.format(result['message']))
        return False


    def add_ticket_to_crits_event(self, event_id, pulse_id, params={},
                                  proxies={}, verify=True):
        '''
        Adds a ticket to the provided CRITs Event
        '''
        submit_url = '{}/api/v1/{}/{}/'.format(self.crits_url, 'events',
                                               event_id)
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


    def build_crits_relationship(self, event_id, indicator_id, params={},
                                 proxies={}, verify=True):
        '''
        Builds a relationship between the given event and indicator IDs
        '''
        submit_url = '{}/api/v1/{}/{}/'.format(self.crits_url, 'events',
                                               event_id)
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

        r = requests.patch(submit_url, proxies=proxies, params=params,
                           data=data, verify=False)
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


    otx2crits = OTX2CRITs(dev=args.dev, config=args.config, days=args.days)
    otx2crits.execute()


if __name__ == '__main__':
    main()
