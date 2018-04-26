import Crypto
from Crypto.PublicKey import RSA
from base64 import b64decode,b64encode
from Crypto.Signature import PKCS1_v1_5 as Signer_PKCS1_v1_5

import json

class Wallet(object):
    def __init__(self):
        self.key = self.key = RSA.generate(1024)
    
    def address(self):
        """
        Return the address of this wallet
        :return: <str> base64-encoded string with the public key of this wallet
        """
        return b64encode(self.key.publickey().exportKey('DER')).decode()    
        
    def tojson(self):
        """
        Return the private and public key of this wallet
        :return: <str> json containing base64-encoded private and public keys of this wallet
        """
        binPrivKey = self.key.exportKey('DER')
        return json.dumps({'publickey': self.address(), 'privatekey': b64encode(binPrivKey).decode()},
                          sort_keys = True, indent = 4)
   
    def fromjson(self, jsonstring):
        """
        Read the private key from a json string
        :param jasonstring: <str> json containing base64-encoded private key of this wallet
        """
        privatekey = json.loads(jsonstring)['privatekey']
        self.key = RSA.importKey(b64decode(privatekey))
    
    def importkey(self, filename):
        """
        Read the private key from a file
        :param filename: <str> path to the file containing the private key
        """
        json_file = open(filename, 'r')
        jasonstring = json_file.read()
        self.fromjson(jasonstring)
    
    def exportkey(self, filename):
        """
        Write the private key to a file
        :param filename: <str> path to the private key should be written to
        """
        with open(filename, 'w') as outfile:
            outfile.write(self.tojson())
        
    def signtransaction(self, amount, recipient):
        """
        Assemble a outgoing transaction and sign it with the private key of this wallet
        :param recipient: <str> Address of the Recipient
        :param amount: <int> Amount
        :return: <str> json containing the signed transaction
        """
        toSign = '{amount='+str(amount)+'|recipient='+str(recipient)+'|sender='+str(self.address())+'}'
        
        digest = Crypto.Hash.SHA256.new()
        digest.update(toSign.encode())
        
        signer = Signer_PKCS1_v1_5.new(self.key)
        cipher_text = signer.sign(digest)
        
        signature = b64encode(cipher_text).decode()
        transaction = {
            'amount': amount,
            'recipient': recipient,
            'sender': self.address(),
            'signature': signature
        }
        return json.dumps(transaction, sort_keys = True, indent = 4)
    
if __name__ == '__main__':
    wallet = Wallet()    
    # wallet.exportkey('key.json')
    wallet.exportkey('workdir/key1.json')
    
    signedtransaction = wallet.signtransaction(10, "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYWamEtBJVt3908Ui2MunXts8Ixj5gGivkchjXRHduiyV95xYURDHBGP7lA+LP1KweUA0JFt3wKtJsMOZKI9sdVloEZguuTwBe57E1HNWNJWE2yaubT6byOzGJG46Oa4fAGV1gxH0UfkjTlDGWnEK/P+Hix+L20i5Fr5miU9sFnwIDAQAB")    
    print(signedtransaction)
    
    #from argparse import ArgumentParser
    #parser = ArgumentParser()
    #parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    #args = parser.parse_args()
    #_port = args.port
    
    
