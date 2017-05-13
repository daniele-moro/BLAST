from merkletools import *
import hashlib
from jsonrpc import ServiceProxy
from secp256k1 import PrivateKey, PublicKey

pubkey="038b0d29cf7ad24aec2b6f9eb9fb3f05c5456625a45395236d334452e3463462a0"

value = "proof"
proof = [{'left': 'c1cda26362828b69266512052b97cb3729e3b052e4ade47c0a1e3383defe73c7'}, {'right': '8befff2dd26a84cbb1d736bdf27e1ff7ad4fc0c4d8ee700d5e77befc02da3cd1'}, {'left': '63cb76322ee0a29a8768b99b09505972dd896be71ab9cc7ebdb9e1963054c3d3'}, {'left': 'c57417e724fd5fc72081059157b65c18ea212d75df5a8225443de9cfece84a9a'}, {'left': '132c3fe5c198d953dcc62ceef2e9289216d24970302b91a67f823972fb6a7541'}, {'right': 'cc53527a1a04293bc39c5f742d9ba27cdba4417633d0aee86ac57b6b45af21db'}]
merkle_root = "4ea854967db56046f49b77c21280e76cb63c390bdaa0f40b5a6a670d2d176853"

tx_id= "d0d955b5a5d67709ecebc9f5a6afcaed844c357d0ecc3a7cc074f1c81f1f00c2"
# epoch = ""
# smh_prev = ""
def hash(string):
    h = hashlib.sha256()
    h.update(string)
    return h.hexdigest()


hash_value = hash(value)
mt = MerkleTools(hash_type="SHA256")
if (mt.validate_proof(proof, hash_value, merkle_root)):
    print "Transparency layer Inclusion has been validated"

# rpc_user = "daniele"
# rpc_pwd = "asdasdasd"
# rpc = ServiceProxy("http://%s:%s@127.0.0.1:18332/" % (rpc_user, rpc_pwd))
#
# tx_hex = rpc.gettransaction(tx_id)['hex']
# btc_smh = tx_hex.split("6a20")[1][:63]
#
# privkey=PrivateKey()
# msg = epoch + smh_prev + merkle_root
# vrf = privkey.pubkey.ecdsa_verify(msg,btc_smh)




