# dns server
Simple DNS server. Only queries of type A are impolemented.
To use this server, you need to start python3 main.py. The initial port is 13337, and ip is set to localhost, but you are able to change it in cfg.py.
You can also change dns root server, if you need it.
Sample of using:


__python3 main.py &__
__dig google.com -p 13337 @127.0.0.1__
