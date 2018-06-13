#! /usr/bin/env python
import requests
import traceback
# import sys
# import logging
import json
import random
import uuid
import string
import time
import threading
from sanction import Client
from bs4 import BeautifulSoup
import jwt
import pytest
import glob
import os
import math
import time
import importlib
import datetime

@pytest.mark.env(['dev'])
def test_basic_custom_exp(config):
    try:
        sample = open('sample.json').read()
        exp = 3600

        r = requests.post(config['signer_uri'] + "/sign?exp={}".format(exp),
                          data=sample, headers=config['headers'], verify=False)
        assert r.status_code == 200, r.text

        verify_jwt(r.text, exp=3600)
    except Exception as e:
        assert False, str(traceback.format_exc())

@pytest.mark.env(['dev'])
def test_basic(config):
    try:
        sample = open('sample.json').read()

        r = requests.post(config['signer_uri'] + "/sign",
                          data=sample, verify=False)
        assert r.status_code == 200, r.text

        verify_jwt(r.text)
    except Exception as e:
        assert False, str(traceback.format_exc())



def verify_jwt(response_received, exp=3600):
    pubkey = open('pubkey.pem').read()
    jwtoken = jwt.decode(response_received, pubkey, algorithms=['RS256'])

    assert jwtoken['aud'] == "*"
    assert jwtoken['iss'] == "https://foooo.com"
    assert jwtoken['sub'] == "08bdda1e-0d4f-4261-9f1b-f9b8d9f817d6"
    assert jwtoken['iat'] is not None
    assert jwtoken['iat'] == jwtoken['nbf']
    assert jwtoken['exp'] == jwtoken['iat'] + exp
