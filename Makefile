all:
	gcc vhost_funcs.c  vhostnetpci_test.c -o xvhostusernet -lpthread 
clean:
	rm -rf  xvhostusernet

