# BLAST
#from jsonrpc import ServiceProxy
from jsonrpc import ServiceProxy
from binascii import hexlify, unhexlify
import hashlib
from merkletools import *
import cPickle as pickle
from secp256k1 import PrivateKey, PublicKey
import random, string
import time
import thread
import requests
import json

EPOCH_TIME=10

gen_tx = "fc64c5ad44c7fd43891392699a5dfd9d499207ee6f073a85e67093897ed79456"

rpc_user = "daniele"
rpc_pwd = "asdasdasd"
rpc = ServiceProxy("http://%s:%s@127.0.0.1:18332/" % (rpc_user, rpc_pwd))

pos_proof = 0


#INPUT DEVE ESSERE hash
def EPOCH_tx(smh):
	if current_tx=="":
		my_tx = gen_tx
	else:
		my_tx = current_tx
	print my_tx

	unspent_txs = rpc.listunspent()
	print rpc.listunspent()
	for utx in unspent_txs:
		if(utx['txid'] in my_tx):
			print utx
			sel_tx = utx
			in_txid = utx['txid']
			in_vout = utx['vout']

	print "Selected transaction: ", sel_tx

	url = 'https://bitcoinfees.21.co/api/v1/fees/recommended'
	r = requests.get(url)
	response = json.loads(r.text)
	estimated_fee = response["halfHourFee"]
	satoshi = 0.00000001
	fee_byte = satoshi * int(estimated_fee)
	byte_size = 235
	fee = fee_byte * byte_size
	change = sel_tx['amount'] - fee
	print "\nInitial amount: ", sel_tx['amount']
	print "Change: ", change
	print "Fee: ", fee

	change_address = rpc.getnewaddress()
	dummy_testnet = "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8"

	raw_tx = rpc.createrawtransaction([{'txid': in_txid, 'vout': in_vout}], {change_address: change, dummy_testnet: 0})

	oldScriptPubKey = "1976a914000000000000000000000000000000000000000088ac"

	#data = "A"*64
	data = smh
	hex_data = data
	print "\nData: ", data
	print "Hex Data: ", hexlify(data)
	print "Hex Data len: ", len(hexlify(data))/2

	newScriptOpReturn = "6a" + hexlify(chr(len(hex_data)/2)) + hex_data
	newScriptOpReturn = hexlify(chr(len(unhexlify(newScriptOpReturn)))) + newScriptOpReturn

	print "New Script is: ", newScriptOpReturn

	raw_tx = raw_tx.replace(oldScriptPubKey, newScriptOpReturn)
	signed_raw_tx = rpc.signrawtransaction(raw_tx)
	signed_raw_tx = signed_raw_tx['hex']

	print "\nThe Signed Raw Transaction is: ", signed_raw_tx, "\n"


	txid = rpc.sendrawtransaction(signed_raw_tx)
	print "The transaction has been accepted with id: ", txid, "\n"
	with open("current_tx.txt", "w") as file:
		file.write(txid)
	return txid


def hash(string):
    h = hashlib.sha256()
    h.update(string)
    return h.hexdigest()

def EPOCH():
	# Load parameters
	with open("server_data.txt", "r") as file:
		prev_smh = file.readline()
		prev_ts = file.readline()
		prev_root = file.readline()
	print prev_smh, prev_ts, prev_root
	t = str(int(prev_ts)+1)

	mt.make_tree()
	root_t = mt.get_merkle_root()
	print mt.get_proof(pos_proof-1)
	print "LEAF_COUNT:" , mt.get_leaf_count()
	signature = sign(t,prev_smh, root_t)
	print 'H(SIGNATURE): ' + signature
	tx_id = EPOCH_tx(hash(signature))
	with open("server_data.txt", "w") as file:
		file.write(signature+"\n")
		file.write(t+"\n")
		file.write(root_t+"\n")

	with open("blast_data_"+t+".txt", "w") as file:
		file.write("epoch: "+ t+"\n")
		file.write("#elements: " + str(mt.get_leaf_count()) + "\n")
		file.write("root: " + root_t + "\n")
		# file.write("SIG: " + signature + "\n")
		# file.write("H(SIG): " + hash(signature) + "\n")
		file.write("tx_id: " + tx_id + "\n")
	backup_merkle(mt)


def sign(t, p_smh, root_t):
	with open('server_crypto') as f:
		content = f.readlines()
	content = [x.strip() for x in content]
	priv = content[0]
	pub = content[1].split(': ')[1]

	privkey = PrivateKey(bytes(bytearray.fromhex(priv)), raw=True)
	msg = t + p_smh + root_t
	sig = privkey.ecdsa_sign(msg)
	sig_der = privkey.ecdsa_serialize(sig)
	return sig_der

# FUNCTION to BACKUP on merkle.p the MERKLE TREE
def backup_merkle(mt_bk):
	with open("merkle.p","w") as fp:
		pickle.dump(mt_bk, fp)

# FUNCTION to LOAD the merkle tree from merkle.p
def load_merkle():
	with open("merkle.p", "r") as fp:
		d = pickle.load(fp)
	return d

def add_value(value):
	mt.add_lead(value, True)

def get_random_values(n,l):
	random_array = []
	for i in range(n):
		random_array.append(''.join(random.choice(string.lowercase) for i in range(l)))
	return random_array


def thread_client():
	while(1):
		print "CLIENT"
		rnd_vals=get_random_values(random.randint(0,10), random.randint(5,15))
		for x in rnd_vals:
			mt.add_leaf(x, True)
		time.sleep(30)


def thread_epoch_gen():
	while 1:
		time.sleep(EPOCH_TIME*60)
		EPOCH()

# ---------------------MAIN-------------------
with open("genesys_tx.txt", "r") as file:
	gen_tx=file.readline()
# print "GEN_TX:",gen_tx
with open("current_tx.txt", "r") as file:
	current_tx=file.readline()
# print "CURRENT_TX:",current_tx

# LOAD del MERKLE TREE
mt = load_merkle()

mt.add_leaf("proof", True)
pos_proof=mt.get_leaf_count()
# mt.add_leaf(hash("FIRST"))
#
#
# # print mt.get_merkle_root()
# # mt = MerkleTools(hash_type="SHA256")
# #
#
# # backup_merkle(mt)
#
# sign("1","2","3")

thread.start_new_thread( thread_client , ())
thread.start_new_thread( thread_epoch_gen, () )

while 1:
	time.sleep(1)
	pass
#EPOCH_tx(hash("CIAO GATTO"))

#EPOCH()



