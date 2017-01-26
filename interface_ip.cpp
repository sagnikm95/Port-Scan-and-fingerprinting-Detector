#include<string>
#include<fstream>
#include<iostream>
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>

using namespace std;

string get_ip(){
	system("ifconfig | grep 'inet addr:' | grep -v 127.0.0.1 | cut -d: -f2| cut -d ' ' -f1 >>sysinfo");
	
	system("ifconfig | grep 'inet addr:' | grep -v 127.0.0.1 | cut -d: -f3| cut -d ' ' -f1 >>sysinfo");

	system("ifconfig | grep 'inet addr:' | grep -v 127.0.0.1 | cut -d: -f4| cut -d ' ' -f1 >>sysinfo");

	const string TBD("unknown");
	string ipAddr( TBD );
	string broadcast( TBD );
	string netmask( TBD );
	ifstream fp("sysinfo");
	if ( fp ){
		if ( fp.peek() != '\0' ) fp >> ipAddr;
		if ( fp.peek() != '\0' ) fp >> broadcast;
		if ( fp.peek() != '\0' ) fp >> netmask;}

	fp.close();
	printf("IP : %s\nGATEWAY : %s\nSUBNET : %s\n",ipAddr.c_str(),broadcast.c_str(),netmask.c_str());
return ipAddr;
}


