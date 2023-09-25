import socket
import threading
import select
import re
import requests

a="\033[1;30m"
b="\033[1;31m"
c="\033[1;32m"
d="\033[1;34m"

e="\033[1;34m"
f="\033[1;35m"
g="\033[1;36m"

add_frind = False
run = False

SOCKS_VERSION = 5

spy_id = False

id_add = None
inter_id = False
clin = None

my_id = None

spy_normall = None

get_id = None

lvl = False

def g5(enc_client_id):
    clin.send(bytes.fromhex(f"050000027108{enc_client_id}100520122ae40408{enc_client_id}12024d4518012004328e0408{enc_client_id}1211212de299a04e45542d424f54e299a02d211a024d4520b6f3d7a6062841308bcbd13038324214e99fe061e8b6ce64a6a3e860c3b5ce64d79ba3614801500158e80768c6dd8dae037a058990c5b00382012408dbdaf1eb04120ad8a7d984d988d8add8b4180720df87d4f0042a0808cb9d85f304100388019dffc4b00392010e010407090a0b120f16191a1e2023980101a801d288f8b103c00101c80101e80106f00112880203920208b609ca13b917f923aa0207080110e7592001aa0208080210963318dc0baa0206080f10a09c01aa0205081710894faa0205081810de3caa0205081a10ba40aa0205081b10b237aa0205081c10b247aa02050820109749aa0205082210ee40aa0205082310a845aa0205082b10cb41aa0206083910fa9801aa0206083d10829c01aa0208084910803218dc0baa0205084d10e432aa0206082110a09c01aa0205083110cb41aa0206084110a09c01aa0206083410a09c01aa0205082810e432aa0205082910e432c2021712041a0201041a0208501a090848120501040506072200ca020e0804106d1858200128f0c0e5a606d00205ea02520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3534333935303432363130353731322f706963747572653f77696474683d313630266865696768743d31363010011801f2020082030b08f8ddcab0032a03108d018a03003a011a403e50056801721e313639313734343639343831393738363933335f3730666e736b733666717801820103303b30880181e08bc5b9d3f4b917a20100a80101b00114"))
    
    gg = f"0811121a08{enc_client_id}10011804203e2a011a400548015203303b306814"
    
 #   group.send(bytes.fromhex("051500000020"+gg))


stop_lvl =b'\x03\x15\x00\x00\x00\x10\t\x1e\xb7N\xef9\xb7WN5\x96\x02\xb0g\x0c\xa8'
team5 = False

head = None

class Proxy:
 
    def __init__(self):
        self.username = "username"
        self.password = "username"
        self.packet = b''
        self.sendmode = 'client-0-'

    def handle_client(self, connection):

        version, nmethods = connection.recv(2)

        methods = self.get_available_methods(nmethods, connection)

        if 2 not in set(methods):

            connection.close()
            return

        connection.sendall(bytes([SOCKS_VERSION, 2]))

        if not self.verify_credentials(connection):
            return

        version, cmd, _, address_type = connection.recv(4)
        

        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
 
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
            name= socket.gethostname()

        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        port2 = port
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
            else:
                connection.close()

            addr = int.from_bytes(socket.inet_aton(
                bind_address[0]), 'big', signed=False)
            port = bind_address[1]

            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')

            ])
        except Exception as e:

            reply = self.generate_failed_reply(address_type, 5)

        connection.sendall(reply)

        if reply[1] == 0 and cmd == 1:
            self.botdev(connection, remote, address, port2)
        connection.close()

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection):
        version = ord(connection.recv(1))


        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')

        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:

            response = bytes([version, 0])
            connection.sendall(response)
 
            return True
            

        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return False

    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def run(self, host, port):
        var = 0 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()
        print(" [ free fire proxy  ] [your ip {}]:[ the port {}]".format(host, port))

        while True:
            conn, addr = s.accept()
            running = False
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()
    def botdev(self, client, remote, address, port):
        global group
        activation = True
        group = None
        # MY ID  d3deadb41e
        
        # d3deadb41e
        global clin
        while True:

            r, w, e = select.select([client, remote], [], [])
            if client in r or remote in r:
                if client in r:
                    dataC = client.recv(999999)
                    
                    if port == 39699:
                        
                        group = remote                        
                        clin = client
                        
                    if remote.send(dataC) <= 0:
                        break
                if remote in r:
                    global actcode

                    dataS = remote.recv(999999)
                    
                    def packet_fixer(packet):
                                                                           packet = packet.lower()
                                                                           packet = packet.replace(" ","")
                                                                           return packet
                                                                           
                                                                           

                    try:
                    	
                    	global a,c,b
                    	global run
                    	global add_frind, spy_id
                    	import random
                    	global id_add , inter_id, my_id
                    	global lvl
                    	global team5 ,spy_normall
                    	global head
                    	
                    	if "0515" in dataC.hex()[0:4] :
                    		print("\n\n ", dataC.hex())
                    	
                    	
                    	if  '0500' in dataS.hex()[0:4] and '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141and len(dataS.hex())>=100:
                    		
                    		spy_normall = dataS
                    		head = client
                    		print("new group")
                    		
                    	
                    	if "0515" in dataC.hex()[0:4] and port == 39699  and len(dataC.hex()) > 800 and "0500" in dataS.hex()[0:4] and len(dataS.hex()) > 1000 and b"https://" in dataS or "0514" in dataC.hex()[0:4] and port == 39699  and len(dataC.hex()) > 800 and "0500" in dataS.hex()[0:4] and len(dataS.hex()) > 1000 and b"https://" in dataS :
                    #		spy_normall = dataS
                    		
                    		print("")
                    	
                    	if "1200" in dataS.hex() [0:4] and  b"/55" in dataS:
                    		print("goo 5 ")
                    		g5(my_id)
                    		
                    	
                    	
                    #	if "c3ffd1e306" in dataS.hex() and port == 39699:
                    		
                    	#	new_id = dataS.hex().replace("d3deadb41e" , "efd2edba0c")
     #               		dataS = bytes.fromhex(new_id)
                    		
                    	#	print(b,"banner dataS : ",dataS.hex())
                    		
                    		
                    	if "c3ffd1e306" in dataC.hex() and port == 39699:
                    		
                    #		new_id= dataC.hex().replace("d3deadb41e" , "efd2edba0c")
                    		
                    #		dataC = bytes.fromhex(new_id)
                    		
                    		
                    		print(c,"\n\n" ,"banner in dataC : " , dataC.hex(),"\n\n")
                    		
                    		
   
                    		                 		
                    		
                    	if "1200" in dataS.hex() [0:4] and  b"/emg" in dataS:
                    		
                    		clin.send(bytes.fromhex("050000002008efd2edba0c100520162a1408c3ffd1e30610c5fab8b1032a0608c3ffd1e306"))
                    		
                    #		print(b,"banner dataS : ",dataS.hex(),"\n\n")
                    		
                    		
                   # 		print(c,"banner in dataC : " , dataC.hex(),"\n\n")
                    		
                    	
                    	if lvl == True :
                    		stop =b'\x03\x15\x00\x00\x00\x10\t\x1e\xb7N\xef9\xb7WN5\x96\x02\xb0g\x0c\xa8'
                    		lvl = False
                    		
                    	if b"showGameBuf" in dataS and "1200" in dataS.hex()[0:4] and port == 39801 and len(dataS.hex()) > 750 and my_id == None :
                    		my_id = dataS.hex()[12:22]
                    		print("\n\n",my_id,"\n\n")
                    		
                    
                    	
                    	
                    	if '0315' in dataC.hex()[0:4]:
                    		if len(dataC.hex()) >=300:
                    			start = dataC
                    			#print(dataC)
                    			serversocket =remote
                    	
                    	if "0515" in dataC.hex()[0:4] and port == 39699  and len(dataC.hex()) > 800 and "0500" in dataS.hex()[0:4] and len(dataS.hex()) > 1000 and b"https://" in dataS :
                    		print("gruop")
                    
                    
                    	
                    	if "1200" in dataS.hex() [0:4] and  b"/++" in dataS:
                    		inter_id = True 
                    	
                    	if "1200" in dataS.hex() [0:4] and  b"/sp" in dataS:
                    		print("input SPY")
                    		
                    		team5 = True
                    		
                    	if inter_id == True :
                    		print("send ++ ")
                    		            		

                    		print("Done ++")
               #     		
                    		
                    		inter_id = False
                    		
                                         	
                    	                    		
                    		
                    	
                    	if "1200" in dataS.hex() [0:4] and  b"/add" in dataS:
                    		print("add True")
                    		add_frind = True
                    		
                    		
                    	
                    	if add_frind == True and port == 39699 and "0f0000" in dataS.hex()[0:6] and len(dataS.hex())  == 52 and "0f15" in dataC.hex()[0:4] and len(dataC.hex()) == 44 :
                    		
                    		print(" SEND Start")
                    		
                    		id_add = dataS.hex()[-10:]
                    		print(id_add)
                    		clin.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b3030464630305d4e4554e385a4424f542b2b5b3030464646465d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))
                    		
                    		
                    		
                    	elif add_frind == True and port == 39699 and "0f0000" in dataS.hex()[0:6] and len(dataS.hex())  < 130 and dataS.hex()[-4:] == "1005" and "0f15" in dataC.hex()[0:4] and len(dataC.hex()) == 44 :
                    		
                    		id_add = dataS.hex()[40:50]
                    		
                    		print(id_add)
                    		
                    		clin.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b3030464630305d4e4554e385a4424f542b2b5b3030464646465d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))
                    		
                    #		39801 :
                    		
                    	import time
                   # 	if port == 39699 :
                    	#	print(id_add)
                    #		print("\n\n",dataS.hex(),"\n\n")
                    #		print ("\n\n",dataC.hex(),"\n\n")
                    		
                    	if team5 == True and port == 39699 and "0f0000" in dataS.hex()[0:6] and len(dataS.hex())  == 52 and "0f15" in dataC.hex()[0:4] and len(dataC.hex()) == 44 and my_id != None:
                    		print("send id spy")
                    		
                    		
                    		
                    		id_add = dataS.hex()[-10:]
                    		
                    		print("id = ", id_add)
                    		
                    		time.sleep(2)
                    		clin.send(bytes.fromhex(f"050000034a08{my_id}100520062abd0608{id_add}12024d451801200332c90208{id_add}12122ee299a04e45542d424f542d5632e299a02e1a024d45208aad91a70628013085cbd13038324218c0b5ce64c091e6608096a36180c38566c09ae06180a897634801500158e80792010a0107090a1216191a1e20980101c00102e801018802049202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2021712041a0201041a0208501a090848120501040506072200ea0204100118018a03020801329e0308{my_id}1209544f502d46495245781a024d45208dad91a70628013085cbd13038324218c09ae061c091e66080a89763c0b5ce6480c385668096a3614801500158e80792010c0107090a0b1216191a1e2023980101c00101e801018802089202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2021712041a0201041a090848120501040506071a0208502200ea02600a5a68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414163485474646955734e6c734b61663451374961457834696a326d722d5f6c5f3564414469486d746c4c696a63626b3d7339362d63100118018a030208013a020116400150016801721e313639323638353936323730303639343537395f35693434747a62647838880180b08c97a8a8f6c017a20100b00114ea010449444331"))
                    		clin.send(bytes.fromhex(f"050000034a08{my_id}100520062abd0608{id_add}12024d451801200332c90208{id_add}12122ee299a04e45542d424f542d5632e299a02e1a024d45208aad91a70628013085cbd13038324218c0b5ce64c091e6608096a36180c38566c09ae06180a897634801500158e80792010a0107090a1216191a1e20980101c00102e801018802049202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2021712041a0201041a0208501a090848120501040506072200ea0204100118018a03020801329e0308{my_id}1209544f502d46495245781a024d45208dad91a70628013085cbd13038324218c09ae061c091e66080a89763c0b5ce6480c385668096a3614801500158e80792010c0107090a0b1216191a1e2023980101c00101e801018802089202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2021712041a0201041a090848120501040506071a0208502200ea02600a5a68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414163485474646955734e6c734b61663451374961457834696a326d722d5f6c5f3564414469486d746c4c696a63626b3d7339362d63100118018a030208013a020116400150016801721e313639323638353936323730303639343537395f35693434747a62647838880180b08c97a8a8f6c017a20100b00114ea010449444331"))
                    		group.send(b'\x05\x03\x00\x00')
                    		
                    #		team5 = False
                    		
                    	
                    	elif team5 == True and port == 39699 and "0f0000" in dataS.hex()[0:6] and len(dataS.hex())  < 130 and dataS.hex()[-4:] == "1005" and "0f15" in dataC.hex()[0:4] and len(dataC.hex()) == 44 and my_id != None:
                    		print("send id spy")
                    		
                    		id_add = dataS.hex()[40:50]
                    		print("id = ", id_add)
                    		time.sleep(2)	
                    		clin.send(bytes.fromhex(f"050000034a08{my_id}100520062abd0608{id_add}12024d451801200332c90208{id_add}12122ee299a04e45542d424f542d5632e299a02e1a024d45208aad91a70628013085cbd13038324218c0b5ce64c091e6608096a36180c38566c09ae06180a897634801500158e80792010a0107090a1216191a1e20980101c00102e801018802049202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2021712041a0201041a0208501a090848120501040506072200ea0204100118018a03020801329e0308{my_id}1209544f502d46495245781a024d45208dad91a70628013085cbd13038324218c09ae061c091e66080a89763c0b5ce6480c385668096a3614801500158e80792010c0107090a0b1216191a1e2023980101c00101e801018802089202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2021712041a0201041a090848120501040506071a0208502200ea02600a5a68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414163485474646955734e6c734b61663451374961457834696a326d722d5f6c5f3564414469486d746c4c696a63626b3d7339362d63100118018a030208013a020116400150016801721e313639323638353936323730303639343537395f35693434747a62647838880180b08c97a8a8f6c017a20100b00114ea010449444331"))
                    		clin.send(bytes.fromhex(f"050000034a08{my_id}100520062abd0608{id_add}12024d451801200332c90208{id_add}12122ee299a04e45542d424f542d5632e299a02e1a024d45208aad91a70628013085cbd13038324218c0b5ce64c091e6608096a36180c38566c09ae06180a897634801500158e80792010a0107090a1216191a1e20980101c00102e801018802049202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2021712041a0201041a0208501a090848120501040506072200ea0204100118018a03020801329e0308{my_id}1209544f502d46495245781a024d45208dad91a70628013085cbd13038324218c09ae061c091e66080a89763c0b5ce6480c385668096a3614801500158e80792010c0107090a0b1216191a1e2023980101c00101e801018802089202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2021712041a0201041a090848120501040506071a0208502200ea02600a5a68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414163485474646955734e6c734b61663451374961457834696a326d722d5f6c5f3564414469486d746c4c696a63626b3d7339362d63100118018a030208013a020116400150016801721e313639323638353936323730303639343537395f35693434747a62647838880180b08c97a8a8f6c017a20100b00114ea010449444331"))
                    		group.send(b'\x05\x03\x00\x00')
                    		
                    	#	team5 = False
                    		
                    		
                    		
                    		
                    		
                    		
                    		

                    		
                    		
                    		
                    		print(" SEND ON")
                    		
                    		
                    	
                    	if add_frind == True :
                    		    
                    		    BNS = ["b2dd8dae03","b1dd8dae03","bfdc8dae03"]
                    		    probabilities = [3.3333, 3.3333, 3.3333]
                    		    B_N = random.choices(BNS, probabilities)[0]
                    		    target_id = "cea8cdcb1a"
                    		#    print("send frinds")
                     		
                    		
                    		
                    		
                    	
                    	
                  #  	if port == 39801 and b"GroupID" in dataS:
                    	#	print("1")
                    		
                    	if run == True and port== 39801 and b"GroupID" in dataS :
                    		new1 = dataS.hex().index("47726f75704944") +18
                    		new3 = dataS.hex().index("2c2247726f7570223a")
                    		new2 = dataS.hex()[new1:new3]
                    		impor = bytes.fromhex(new2)
                    		id = b"6994113211"
                    		dataS = dataS.replace(impor, id)
                    #		print(dataS)
                    	#	print(bytes.fromhex(new2))
                    		
                   		# 1708019451
                   		
                  	 
                     		
                    	if "1200" in dataS.hex()[0:4] and port == 39801 and len(dataS.hex()) > 750 and my_id == None :
                    		
                    		my_id = dataS.hex()[12:22]
                    #		print(my_id)
                    		
                    		
                    		              	
                    	
                    except:
                        print("rerror")

                    if client.send(dataS) <= 0:
                        break	 
                                        
def starttopbot():

    Proxy().run('127.0.0.1',7777)
starttopbot()
