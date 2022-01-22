#Makefile
all: pcap

pcap:
		gcc pcap-test.c -o pcap-test -lpcap

clean:
		rm -rf pcap-test