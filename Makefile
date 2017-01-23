all:
	gcc vhost_funcs.c  -g vhostnetpci_test.c -o xvhostusernet -lpthread 
clean:
	rm -rf  xvhostusernet

