all:
	gcc -O0 vhost_funcs.c  pcap_rxtx.c -g vhostnetpci_test.c -o xvhostusernet -lpthread -lpcap 
clean:
	rm -rf  xvhostusernet

