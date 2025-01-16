import json
import time
import os
import base64
import datetime
import json
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
import nacl.hash
from nacl.signing import SigningKey
from cryptography.hazmat.primitives import serialization
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from flask import Flask, request, render_template
import requests
import uuid
import multiprocessing
import threading
import pytz
import cryptic_utils

bapBaseUrl = os.getenv("BAP_BASE_URL")
bppBaseUrl = os.getenv("BPP_BASE_URL")
registry_url = os.getenv("REGISTRY_URL")
app_port = os.getenv("APP_PORT")
static_file_port = os.getenv("STATIC_FILE_PORT")
search_url = os.getenv("SEARCH_URL")
subscribers = None
subscribers_uniquekey_store = {}

bapSubscribeBody = {
    "context": {
        "operation": {
            "ops_no": 1
        },
    },
    "message": {
        "request_id": "",
        "timestamp": "",
        "entity": {
            "gst": {
                "legal_entity_name": "Example Corp",
                "business_address": "Bengaluru",
                "city_code": [
                    "std:080"
                ],
                "gst_no": "29FIICR9895F4Z9"
            },
            "pan": {
                "name_as_per_pan": "Anil Sharma",
                "pan_no": "BAJPC4350M",
                "date_of_incorporation": "15/11/2024"
            },
            "name_of_authorised_signatory": "Anil Sharma",
            "email_id": "email@domain.in",
            "mobile_no": 9999999990,
            "country": "IND",
            "subscriber_id": "",
            "unique_key_id": "",
            "callback_url": "/dev",
            "key_pair": {
                "signing_public_key": "",
                "encryption_public_key": "",
                "valid_from": "",
                "valid_until": "2030-06-19T11:57:54.101Z"
            }
        },
        "network_participant": [
            {
                "subscriber_url": "/dev",
                "domain": "ONDC:FIS12",
                "type": "buyerApp",
                "msn": False,
                "city_code": []
            }
        ]
    }
}

bppSubscribeBody = {
    "context": {
        "operation": {
            "ops_no": 2
        }
    },
    "message": {
        "request_id": "",
        "timestamp": "",
        "entity": {
            "gst": {
                "legal_entity_name": "Example Corp",
                "business_address": "Bengaluru",
                "city_code": [
                    "std:080"
                ],
                "gst_no": "29FIICR9895F4Z9"
            },
            "pan": {
                "name_as_per_pan": "Anil Sharma",
                "pan_no": "BAJPC4350M",
                "date_of_incorporation": "15/11/2024"
            },
            "name_of_authorised_signatory": "Anil Sharma",
            "email_id": "email@domain.in",
            "mobile_no": 9999999990,
            "country": "IND",
            "subscriber_id": "",
            "unique_key_id": "",
            "callback_url": "/dev",
            "key_pair": {
                "signing_public_key": "",
                "encryption_public_key": "",
                "valid_from": "",
                "valid_until": "2030-06-19T11:57:54.101Z"
            }
        },
        "network_participant": [
            {
                "subscriber_url": "/dev",
                "domain": "ONDC:TRV10",
                "type": "sellerApp",
                "msn": False,
                "city_code": []
            }
        ]
    }
}

searchBody = {
  "context": {
    "domain": "ONDC:FIS12",
    "location": {
      "country": {
        "code": "IND"
      },
      "city": {
        "code": "*"
      }
    },
    "transaction_id": "a9aaecca-10b7-4d19-b640-b047a7c62196",
    "message_id": "bb579fb8-cb82-4824-be12-fcbc405b6608",
    "action": "search",
    "timestamp": "2024-12-02T19:43:03.443Z",
    "version": "2.0.1",
    "bap_uri": "https://ondc.roywrito.people.aws.dev/",
    "bap_id": "ondc.roywrito.people.aws.dev",
    "ttl": "PT10M"
  },
  "message": {
    "intent": {
      "category": {
        "descriptor": {
          "code": "PERSONAL_LOAN"
        }
      },
      "payment": {
        "collected_by": "BPP",
        "tags": [
          {
            "descriptor": {
              "code": "BUYER_FINDER_FEES"
            },
            "display": "false",
            "list": [
              {
                "descriptor": {
                  "code": "BUYER_FINDER_FEES_TYPE"
                },
                "value": "percent-annualized"
              },
              {
                "descriptor": {
                  "code": "BUYER_FINDER_FEES_PERCENTAGE"
                },
                "value": "1"
              }
            ]
          },
          {
            "descriptor": {
              "code": "SETTLEMENT_TERMS"
            },
            "display": "false",
            "list": [
              {
                "descriptor": {
                  "code": "DELAY_INTEREST"
                },
                "value": "2.5"
              },
              {
                "descriptor": {
                  "code": "STATIC_TERMS"
                },
                "value": "https://bap.credit.becknprotocol.io/personal-banking/loans/personal-loan"
              },
              {
                "descriptor": {
                  "code": "OFFLINE_CONTRACT"
                },
                "value": "true"
              }
            ]
          }
        ]
      }
    }
  }
}

def sign(signing_key, private_key):
    private_key64 = base64.b64decode(private_key)
    seed = crypto_sign_ed25519_sk_to_seed(private_key64)
    signer = SigningKey(seed)
    signed = signer.sign(bytes(signing_key, encoding='utf8'))
    signature = base64.b64encode(signed.signature).decode()
    return signature


def decrypt(enc_public_key, enc_private_key, cipherstring):
    private_key = serialization.load_der_private_key(
        base64.b64decode(enc_private_key),
        password=None
    )
    public_key = serialization.load_der_public_key(
        base64.b64decode(enc_public_key)
    )
    shared_key = private_key.exchange(public_key)
    cipher = AES.new(shared_key, AES.MODE_ECB)
    ciphertxt = base64.b64decode(cipherstring)
    return unpad(cipher.decrypt(ciphertxt), AES.block_size).decode('utf-8')


def createHtml(subscriber, subscriber_id):
    signature = sign(subscriber['requestId'], subscriber['signingPrivateKey'])
    htmlFile = f'''
    <html>
        <head>
            <meta name= "ondc-site-verification" content="{signature}" />
        </head>
        <body>
            ONDC Site Verification Page
        </body>
    </html>
    '''
    if subscriber['type'] == "BAP":
        if not os.path.exists(f'templates/{subscriber_id[slice(len(bapBaseUrl) + 1, len(subscriber_id))]}'):
            os.makedirs(
                f'templates/{subscriber_id[slice(len(bapBaseUrl) + 1, len(subscriber_id))]}')
        with open(f"templates/{subscriber_id[slice(len(bapBaseUrl) + 1, len(subscriber_id))]}/ondc-site-verification.html", "w+") as file:
            file.write(htmlFile)
        #with open(f"/usr/share/nginx/html/ondc-site-verification.html", "w+") as file:
            #file.write(htmlFile)
    elif subscriber['type'] == "BPP":
        if not os.path.exists(f'templates/{subscriber_id[slice(len(bppBaseUrl) + 1, len(subscriber_id))]}'):
            os.makedirs(
                f'templates/{subscriber_id[slice(len(bppBaseUrl) + 1, len(subscriber_id))]}')
        with open(f"templates/{subscriber_id[slice(len(bppBaseUrl) + 1, len(subscriber_id))]}/ondc-site-verification.html", "w+") as file:
            file.write(htmlFile)


app = Flask(__name__)


@app.route('/on_subscribe', methods=['POST'])
def onsubscribe():
    data = request.get_json()
    print(f"/on_subscribe called :: Request -> {data}")
    subscriber_id = data['subscriber_id']
    unique_key_id = subscribers_uniquekey_store[subscriber_id]
    subscriber = subscribers[f"{subscriber_id} | {unique_key_id}"]
    print(subscriber)
    return {
        "answer": decrypt(subscriber['ondcPublicKey'], subscriber['encPrivateKey'], data['challenge'])
    }


def serve_file():
    os.system(
        f'python -m http.server {static_file_port} --directory templates')


def subscribe_helper():
    if subscribers != None:
        global subscribers_uniquekey_store
        for subscriber_uk_id, subscriber in subscribers.items():
            [subscriber_id, unique_key_id] = subscriber_uk_id.split(' | ')
            subscribers_uniquekey_store[subscriber_id] = unique_key_id
            request_id = str(uuid.uuid4())
            subscribers[subscriber_uk_id]['requestId'] = request_id
            createHtml(subscriber, subscriber_id)
        process = multiprocessing.Process(target=serve_file)
        process.start()
        time.sleep(5)
        for subscriber_uk_id, subscriber in subscribers.items():
            [subscriber_id, unique_key_id] = subscriber_uk_id.split(' | ')
            request_id = subscriber['requestId']
            current_datetime = datetime.datetime.now().astimezone(pytz.timezone('Asia/Kolkata'))
            current_datetime_iso8601 = current_datetime.strftime(
                "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            if subscriber['type'] == 'BAP':
                bapSubscribeBody['message']['request_id'] = request_id
                bapSubscribeBody['message']['timestamp'] = current_datetime_iso8601
                bapSubscribeBody['message']['entity']['subscriber_id'] = subscriber_id
                bapSubscribeBody['message']['entity']['unique_key_id'] = unique_key_id
                bapSubscribeBody['message']['entity']['key_pair']['signing_public_key'] = subscriber['signingPublicKey']
                bapSubscribeBody['message']['entity']['key_pair']['encryption_public_key'] = subscriber['encPublicKey']
                bapSubscribeBody['message']['entity']['key_pair']['valid_from'] = current_datetime_iso8601
                bapSubscribeBody['message']['network_participant'][0]['city_code'] = [
                    subscriber['city']]

                print(json.dumps(bapSubscribeBody))

                response = requests.post(registry_url, json=bapSubscribeBody)
                if response.status_code == 200:
                    print(
                        f"/subscribe for {subscriber_uk_id} request successful :: {response.json()}")
                else:
                    print(
                        f"/subscribe for {subscriber_uk_id} request failed :: {response.json()}")
            elif subscriber['type'] == 'BPP':
                bppSubscribeBody['message']['request_id'] = request_id
                bppSubscribeBody['message']['timestamp'] = current_datetime_iso8601
                bppSubscribeBody['message']['entity']['subscriber_id'] = subscriber_id
                bppSubscribeBody['message']['entity']['unique_key_id'] = unique_key_id
                bppSubscribeBody['message']['entity']['key_pair']['signing_public_key'] = subscriber['signingPublicKey']
                bppSubscribeBody['message']['entity']['key_pair']['encryption_public_key'] = subscriber['encPublicKey']
                bppSubscribeBody['message']['entity']['key_pair']['valid_from'] = current_datetime_iso8601
                bppSubscribeBody['message']['network_participant'][0]['city_code'] = [
                    subscriber['city']]

                print(json.dumps(bppSubscribeBody))

                response = requests.post(registry_url, json=bppSubscribeBody)
                if response.status_code == 200:
                    print(
                        f"/subscribe for {subscriber_uk_id} request successful :: {response.json()}")
                else:
                    print(
                        f"/subscribe for {subscriber_uk_id} request failed :: {response.json()}")
        time.sleep(300)
        process.terminate()
        process.join()

@app.route('/on_search', methods=['POST'])
def onsearch():
    data = request.get_json()
    print(f"/on_search called :: Request -> {data}")
    # subscriber_id = data['subscriber_id']
    # unique_key_id = subscribers_uniquekey_store[subscriber_id]
    # subscriber = subscribers[f"{subscriber_id} | {unique_key_id}"]
    # print(subscriber)
    # return {
    #     "answer": decrypt(subscriber['ondcPublicKey'], subscriber['encPrivateKey'], data['challenge'])
    # }
    return {"success": "ACK"}

def search_helper():
    request_id = str(uuid.uuid4())
    current_datetime = datetime.datetime.now().astimezone(pytz.timezone('Asia/Kolkata'))
    current_datetime_iso8601 = current_datetime.strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    searchBody['context']['transaction_id'] = request_id
    searchBody['context']['message_id'] = request_id
    searchBody['context']['timestamp'] = current_datetime_iso8601
    # searchBody['context']['bap_id'] = subscriber_id
    # searchBody['context']['bap_uri'] = subscriber['bapUrl']
    auth = cryptic_utils.create_authorisation_header(json.dumps(searchBody))
    print(auth)
    print(json.dumps(searchBody))

    response = requests.post(search_url, headers={'Content-Type':'application/json', 'Authorization': auth}, json=searchBody)
    if response.status_code == 200:
        print(
            f"/search request successful :: {response.json()}")
    else:
        print(
            f"/search request failed :: {response.json()}")
            

@app.route('/subscribe', methods=['POST'])
def subscribe():
    global subscribers
    subscribers = request.get_json()
    print(f"/subscribe called :: Request -> {subscribers}")
    thread1 = threading.Thread(target=subscribe_helper)
    thread1.start()
    return {"success": "ACK"}

@app.route('/search', methods=['POST'])
def search():
    thread1 = threading.Thread(target=search_helper)
    thread1.start()
    return {"success": "ACK"}

@app.route('/ondc-site-verification.html', methods=['GET'])
def verify_html():
    return render_template('ondc-site-verification.html')


def start_flask_app():
    #context = (r'/home/ec2-user/reference-implementations/utilities/on_subscibe-service/python/ssl/cert.pem', r'/home/ec2-user/reference-implementations/utilities/on_subscibe-service/python/ssl/cert.key')
    app.run(port=app_port, host="ondc.roywrito.people.aws.dev")


if __name__ == '__main__':
    start_flask_app()
