Artist, haoj@cernet.com have told you:
--------------------------------------

1) create privkey.pem
	openssl genrsa -out privkey.pem 2048

2) create cacert.pem 
	openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095

3) EXEC:
	./ssl_srv -p 7838 -r privkey.pem -c cacert.pem
	./ssl_cli 127.0.0.1 7838

4) TEST:
cli) nid:80002ac711
cli) nid:80002ac711;ans:yes;nonce:197869619
$ ./mymd5 passwd + 197869619
$ 7dfea216fabdb7343df902b68e14617b
cli) nid:herq;digest:7dfea216fabdb7343df902b68e14617b;mac:14FEB5EF2E8D
cli) nid:herq;auth:yes;hmac:a06e447b3ddf9c4d5e3196b6713482ca127feccc9bccd4a2ffe054c2aaf

