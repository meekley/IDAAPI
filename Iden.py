#!/usr/bin/python

import urllib3
import json
import requests


class IDA:
    """ 
    This class is for interacting with Check Points Identity Awareness API on Gateway

    Attributes: 
        gw_ip (string): IP address of the firewall gateway 
        secret (string): Identity Awareness secret for authentication to gateway API
    
    Methods:
        ida_add(self, host_ip, host_tag, role_object, timeout)
        ida_show(self, ip)
        ida_delete(self, ip)
    """

    # TODO: add SSL verification with a cert

    def __init__(self, gw_ip, secret, ssl_disable=False):
        """ 
        Class constructor

        Parameters:
        gw_ip (string): IP address of the firewall gateway with Identity Awareness API enabled
        secret (string): Identity Awareness secret for authentication to gateway API
        ssl (bool): ssl cert verification - current default is True
        """
        if ssl_disable:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.secret = secret
        self.api_url = 'https://' + gw_ip + '/_IA_API/'
        self.headers = {'Content-type': 'application/json', 'Accept': 'IDA'}

    def ida_add(self, host_ip, host_tag, role_object, timeout):
        """ 
        Method to add identity.
  
        Parameters: 
            host_ip(string): host IP address
            host_tag(string): identity tag
            role_object(string): access role object used in the rulebase
            timeout (string): identity timeout in seconds (300 seconds is minimum)
          
        Returns: 
            On success - status code (200), ip-address added, IDA API message
            On failure - if incorrect client secret - status code 404 and IDA API message
                         if any of the ida_add API call parameters not in allowed format, returns status 400 and the error
                         message
                         if a connection / network issue, returns message "connection error"
        """

        id_url = self.api_url + 'add-identity'
        data = {'shared-secret': self.secret, 'ip-address': host_ip, 'machine': host_tag, 'calculate-roles': 0,
                'session-timeout': int(timeout), 'fetch-machine-groups': 0, 'roles': [role_object]}

        try:
            r = requests.post(id_url, data=json.dumps(data), headers=self.headers, verify=False, timeout=5)
            r.raise_for_status()
            return {'code': r.status_code, 'ip': json.loads(r.content).get('ipv4-address'),
                    'content': json.loads(r.content).get('message')}
        except requests.exceptions.ConnectionError:
            message_string = json.dumps({'message': 'connection error'})
            return json.loads(message_string)
            # wrong gateway IP, gateway does not allow connection, IDA blade is not enabled
        except requests.exceptions.HTTPError:
            if r.status_code == 500 and r.content:
                s_code = 400
                message = r.json()
            else:
                message = json.loads(json.dumps({'message': 'wrong secret'}))
                s_code = r.status_code
            return s_code, message

    def ida_show(self, ip):
        """ 
        Method to show identity.
  
        Parameters: 
            ip (string): host IP address
        
        Returns: 
            On success - status code (200), access role object(s) that IP is part of, tags attached
            On failure - if incorrect client secret - status code 404 and IDA API message
                         if any of the ida_add API call parameters not in allowed format, returns status 400 and
                         the error message
                         if a connection / network issue, returns message "connection error"
        """
        id_url = self.api_url + 'show-identity'
        data = {'shared-secret': self.secret, 'ip-address': ip, }
        try:
            r = requests.post(id_url, data=json.dumps(data), headers=self.headers, verify=False, timeout=5)
            r.raise_for_status()
            resp = r.json()
            respon = {'tags': resp.get('machine'), 'roles': resp.get('combined-roles'), }

            return r.status_code, json.loads(json.dumps(respon))

        except requests.exceptions.ConnectionError:

            message_string = json.dumps({'message': 'connection error'})
            return json.loads(message_string)
            # wrong gateway IP, gateway does not allow connection, IDA blade is not enabled
        except requests.exceptions.HTTPError:

            if r.status_code == 500 and r.json()['message'] == 'total 0 user records were found.':
                s_code = 200
                message = r.json()

            elif r.status_code == 500 and r.content:
                s_code = 400
                message = r.json()['message']

            else:
                message = json.loads(json.dumps({'message': 'wrong secret'}))
                s_code = r.status_code
            return s_code, message

    def ida_delete(self, ip):
        """ 
        Method to delete identity.
  
        Parameters: 
            ip(string): host IP address
        
        Returns: 
            On success - status code (200), access role object(s) that IP is part of, tags attached
            On failure - if incorrect client secret - status code 404 and IDA API message
                         if any of the ida_add API call parameters not in allowed format, returns status 400 and
                         the error message
                         if a connection / network issue, returns message "connection error"
        """

        id_url = self.api_url + 'delete-identity'
        data = {'shared-secret': self.secret, 'ip-address': ip, }
        try:
            r = requests.post(id_url, data=json.dumps(data), headers=self.headers, verify=False, timeout=5)
            r.raise_for_status()
            return r.status_code, json.loads(r.content)
        except requests.exceptions.ConnectionError as err:

            message_string = json.dumps({'message': 'connection error'})
            return json.loads(message_string)
            # wrong gateway IP, gateway does not allow connection, IDA blade is not enabled
        except requests.exceptions.HTTPError as err:

            if r.status_code == 500 and r.content:
                s_code = 400
                message = r.json()['message']

            else:
                message = json.loads(json.dumps({'message': 'wrong secret'}))
                s_code = r.status_code
            return s_code, message
            # wrong secret (404), wrong time-put value (500)
