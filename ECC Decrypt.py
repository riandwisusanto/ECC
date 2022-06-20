from ecies import decrypt
import time

dec = decrypt('0x6b72e24ba2329768360e3e1bb99ece736fcc1885967616fcb00cdfe025683bda', 
              b'\x04\xd6\xdb\xe0`F\xedC\xf71\\~\xde\t\xe3\xb96H}\xb6\xdaY\xfa\x8b[v\x16\xd8\xc6T\xfaH.\x02\xe4\xd7A~\xcdk\x17s%\xdfbC,\xc2\x7f\x8e\xe3\x8c>\\\xff\xdakD\xec\x0c2f+/s\x0b\xa1\x12U\xfdi\xe0\xef\x96\x87\xc1\xed\x8fw\xc7\xcc\xa4\xde\xf1\x10\xab@\xa8\xa7\xa2\xa4\x9d\xdd\x8f\xc7*\xc9_\xa4\xba\x15W')
decrypt_time = time.time()
print("Decrypt Text  : ", dec.decode("utf-8"))
print("Time Execute  :  %s seconds" % (time.time() - decrypt_time))