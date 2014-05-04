import urllib2
import sys

cypher = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
TARGET = 'http://crypto-class.appspot.com/po?er='
iv  = 'f20bdba6ff29eed7b046d1df9fb70000'
c0  = '58b1ffb4210a580f748b4ac714c001bd'
c1  = '4a61044426fb515dad3f21f18aa577c0'
c2  = 'bdf302936266926ff37dbf7035d5eeb4'
global pt
binary_c1 = c1.decode("hex")
binary_c2= c2.decode("hex")
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def lengthpad(self):
		 rori = strXarr(c1,2)
		 r = strXarr(c1,2)
		 padstr = gen_string(1,32)
		 padarr = strXarr(padstr,2)
		 
		 for g in range(0,256):
			 
			 r[15] = '{0:02x}'.format(g ^ int(r[15],16) ^ int(padarr[15],16))
			 if self.query((c0 + arrXstr(r) + c2)):
				 break
			 else:
				 print False
			 r[15] = rori[15]
			 print g
		 		 
		 num = 255
		 #mirar length padding
		 for i in range(15):
		     aux = r[i]

		     r[i] = '{0:02x}'.format(int(r[i],16) ^ num)
		     #print 'r^: ',r
		     q = (c0 + arrXstr(r) + c2)
		     print 'i: ',i
		     if self.query(q):

		        r[i] = aux
		     else:
		        lenpad =16-i		
		        break

		 			 	 
		 print 'Padding length: ',lenpad			 	 
		 return [lenpad,rori];		 

    def crnextbyte(self,s,pos):
		lenpad = s[0]
		lastp2primaArr = s[2]

		rori = s[1] #a
		r = s[1]
		#print rori
		#print 'lastp2primaArr: ',lastp2primaArr

		print '<<<<<<'
		print r

		for g in range (0,256):
			#print '$$$$$$$$'
			p2primaArr = strXarr(gen_string(lenpad+1,32),2)

			print g

			p2primaArr[15-lenpad] = '{0:02x}'.format(int(p2primaArr[15-lenpad],16)^g) #g xor p2primapad

			c1prima = arrXor(arrXor(p2primaArr,r),lastp2primaArr)

			if pos == 0:
				queryArg = arrXstr(c1prima) + c0

			elif pos ==1:
				queryArg = iv + arrXstr(c1prima) + c1
			else:
				queryArg = iv + c0 + arrXstr(c1prima) + c2
				
			
			if self.query(queryArg):
				lastp2primaArr[15-lenpad] = '{0:02x}'.format(g) #g xor p2primapad
				return [lenpad+1,rori,lastp2primaArr,chr(g)]
				
			else:
				print False

 
    def query(self, q):
        target = TARGET + urllib2.quote(q)    # Create query URL
        req = urllib2.Request(target)         # Send HTTP request to server
        try:
            f = urllib2.urlopen(req)          # Wait for response
            #print f
        except urllib2.HTTPError, e:          
            print "We got: %d" % e.code       # Print response code
            if e.code == 404:
                return True # good padding
            return False # bad padding



def gen_string(val,lenblock):
	 msg = ('{0:02x}'.format(val)).decode('hex') * val
	 msge = msg.encode('hex')
	 lastmsg = '0' * (lenblock-len(msge)) + msge

	 return lastmsg

def strXarr(stri,n):
	return [stri[i:i+n] for i in range(0, len(stri), n)]

def arrXstr(arr):
    return "".join(arr)

def arrXor(x,y):
    return ['{0:02x}'.format(int(a,16) ^ int(b,16)) for (a,b) in zip(x,y)]


if __name__ == "__main__":
	
	pt = ''
	po = PaddingOracle()
	arg = (iv + c0 + c1 + c2).encode('hex')
	if po.query(arg) == True:
		print "pad true"
	else:
		

					
		r = po.lengthpad()
		print r[0]
		ptarray = strXarr(gen_string(0,32),2)
		for h in range(r[0]): #plainttextarray  generate with padding
			ptarray[15-h] = '{0:02x}'.format(r[0])
	
		r.append(ptarray)

		while r[0]<(15+1):
			r = po.crnextbyte(r,2)
			pt = r[3] + pt
		print 'pt: ',pt
			
		
		
		

		r[0] = 0
		r[1] = strXarr(c0,2)
		r[2] = strXarr(gen_string(0,32),2)
		
		
		

		while r[0]<(15+1):
			r = po.crnextbyte(r,1)
			pt = r[3] + pt
		print 'pt: ',pt
		
		
		

		
		
		r[0] = 0
		r[1] = strXarr(iv,2)
		r[2] = strXarr(gen_string(0,32),2)
		
		while r[0]<(15+1):
			r = po.crnextbyte(r,0)
			pt = r[3] + pt
			print 'pt: ',pt
			print r
