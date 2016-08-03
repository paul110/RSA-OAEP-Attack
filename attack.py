import sys, subprocess, hashlib, math, binascii
oracleCalls = 0

def interact( label, G ) :
  global oracleCalls
  label = "{0:X}".format(label)
  if len(label) %2 ==1 :
      label = "0" + label
  G = formString.format(G)
  oracleCalls+=1

  target_in.write(label + "\n")
  target_in.write(G + "\n" )
  target_in.flush()

  r = int( target_out.readline().strip() )

  return r

def ceilDiv(a, b):
    rest = a % b
    if rest > 0:
        result = (a-rest)/b + 1
    else :
        result = a/ b
    return result

def floorDiv(a, b):
    rest = a%b
    return (a-rest) / b



def attack1(n, e, label, targetC):
    k = int(math.ceil(math.log(n, 256)))
    B = 2**(8*(k-1))

    # ------------Step 1---------------
    f1 = 2
    res = -1
    while res != 1 :
        candidate = targetC * pow(f1, e, n) % n
        res = interact(label, candidate)
        if res != 1 :
            f1 = f1*2
    f1 = f1/2
    print "decided lower bound, total calls: " + str(oracleCalls)

    #------------- step 2--------------
    f2 = (f1 * floorDiv(n + B, B)) %n

    # while < B
    while res == 1 :
        candidate = (targetC * pow(f2, e, n)) % n
        res = interact(label, candidate)
        if res == 1:
            f2 = (f2 + f1) %n
    # print (res, 2)
    print "decided upper bound, total calls: " + str(oracleCalls)

    #-------------- step3--------------------
    # set minimum for range
    mMin = ceilDiv(n, f2)
    # set maximum for range
    mMax = floorDiv(n + B, f2)


    # while there is more than 1 number in the range
    while mMin != mMax:
        ftmp = floorDiv(2*B, mMax -mMin)
        i = floorDiv(ftmp * mMin, n)
        f3 = ceilDiv(i*n, mMin)
        candidate = (targetC * pow(f3, e, n)) %n
        res = interact(label, candidate)
        if res == 1:
            mMin = ceilDiv(i*n + B, f3)
        else :
            mMax = floorDiv(i* n + B, f3)
    print "found encoded message,  total calls: " + str(oracleCalls)

    # encoded message recoverd
    targetMessage = mMax
    octetMessage =  formString.format(targetMessage)

    OAEPDecode(octetMessage, label)

    return

def OAEPDecode( EM, P):
    k = int(math.ceil(math.log(n, 256)))

    emLen = len(EM)
    hashLen = hashlib.sha1("").digest_size

    if emLen/2 < 2*hashLen+2:
        raise Exception("Decoding error")
    maskedSeed = EM[2:(2*hashLen+2)]
    maskedDB   = EM[(2*hashLen+2):]

    seedMask = MGF(maskedDB, 2*hashLen)
    seed = "{0:X}".format(int(maskedSeed, 16) ^ int(seedMask, 16))

    dbMask  = MGF(seed, 2*k-2*hashLen-2)
    DB = "{0:X}".format(int(maskedDB,16) ^ int(dbMask, 16))

    # retain the hash'
    hashNew = DB[:2*hashLen]

    P =  "{0:X}".format(P)
    if( long(hashNew, 16) == long(hashlib.sha1(P.decode('hex')).hexdigest() ,16 )):
        # take the hash' out from the beggining of the input
        DB = DB[2*hashLen:]

        # take the 0s which padd the message out and take the first 1 out as well
        while DB[0] == "0":
            DB = DB[1:]

        # print remaining (message)
        print "decoded message is :  " + DB[1:]
    else :
        raise Exception("Decoding error")
    return

def xor( s1, s2):
    result = ''
    for i in range( 0, min(len(s1), len(s2))):
        result  = result + chr(ord(s1[i]) ^ ord(s2[i]))
    return result


def MGF(z, l):
    hlen = hashlib.sha1("").digest_size *2
    if l > (2**32)*hlen :
        raise Exception("mask too long")
    T = ''
    for i in range (0, ceilDiv(l, hlen)):
        c = I2OSP(i, 4)
        T = T + hashlib.sha1((z + c).decode('hex')).hexdigest()
        # print (z + c)
    if len(T) < l :
        raise Exception("T is too short.")
    return T[:l]

# converts integers to octet strings
def I2OSP(x, xLen):
    if x >= (256**(xLen-1)):
        raise Exception("Number too long")

    result = "%x" % x
    return result.zfill(2*xLen)


if ( __name__ == "__main__" ) :
    if len(sys.argv) < 3 :
      raise Exception("not enough argv")

    inputFile = open(sys.argv[2])
    n = int(inputFile.readline(), 16)
    e = int(inputFile.readline(), 16)
    label = int(inputFile.readline(), 16)
    targetC = int(inputFile.readline(), 16)
    inputFile.close()

  # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )
  #
  # # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

  # Execute a function representing the attacker.
    global modLength
    global formString
    modLength = len("{0:X}".format(n))
    formString = "{0:0"+str(modLength)+"X}"
    attack1(n, e, label, targetC)
