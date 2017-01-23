#include<pcap.h>

pcap_t *pcap_init(char *iname);
void *pcap_rx_thread(void *args);
void pcap_tx(pcap_t *handle, void *packet,int size);
