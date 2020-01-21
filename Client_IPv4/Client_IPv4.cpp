// UDP client that uses blocking sockets

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <map>
#include "conio.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define SERVER_IP_ADDRESS "127.0.0.1"		// IPv4 address of server
#define SERVER_PORT 27015					// Port number of server that will be used for communication with clients
#define BUFFER_SIZE 512						// Size of buffer that will be used for sending and receiving messages to client

std::map<int, char> encode_map;

void encode(char* buff, int buff_size)
{
	for(int i = 0; i < buff_size; i++)
	{

		for (auto it = encode_map.begin(); it != encode_map.end(); it++)
		{
			if(buff[i] == it->second || buff[i] == (it->second + 32))
            {
                //printf("buff = %c\t it = %c\n", buff[i], it->second);
                buff[i] = it->first;
            }

		}
	}
}

void decode(char* buff, int buff_size)
{
	for(int i = 0; i < buff_size; i++)
	{
		for (auto it = encode_map.begin(); it != encode_map.end(); it++)
		{
			if(buff[i] == it->first)
            {
                //printf("buff = %c\t it = %c\n", buff[i], it->second);
                buff[i] = it->second;
            }

		}
	}
}

void fill_map()
{
	encode_map[95] = 'A';
	encode_map[63] = 'B';
	encode_map[29] = 'C';
	encode_map[57] = 'D';
	encode_map[98] = 'E';
	encode_map[25] = 'F';
	encode_map[26] = 'G';
	encode_map[27] = 'H';
	encode_map[59] = 'I';
	encode_map[11] = 'J';
	encode_map[22] = 'K';
	encode_map[96] = 'L';
	encode_map[38] = 'M';
	encode_map[40] = 'N';
	encode_map[33] = 'O';
	encode_map[64] = 'P';
	encode_map[47] = 'Q';
	encode_map[43] = 'R';
	encode_map[17] = 'S';
	encode_map[91] = 'T';
	encode_map[23] = 'U';
	encode_map[18] = 'V';
	encode_map[36] = 'W';
	encode_map[94] = 'X';
	encode_map[41] = 'Y';
	encode_map[50] = 'Z';
	encode_map[42] = ' ';
}
int main()
{
	fill_map();
    // Server address structure
    sockaddr_in serverAddress;
	int offset_bytes, send_length, send_times, i = 0; //variables for choosing file segment to send
    // Size of server address structure
	int sockAddrLen = sizeof(serverAddress);

	// Buffer that will be used for sending and receiving messages to client
    char dataBuffer[BUFFER_SIZE];

	// WSADATA data structure that is used to receive details of the Windows Sockets implementation
    WSADATA wsaData;
    
	// Initialize windows sockets for this process
	int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    
	// Check if library is succesfully initialized
	if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

   // Initialize memory for address structure
    memset((char*)&serverAddress, 0, sizeof(serverAddress));		
    
	 // Initialize address structure of server
	serverAddress.sin_family = AF_INET;								// IPv4 address famly
    serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP_ADDRESS);	// Set server IP address using string
    serverAddress.sin_port = htons(SERVER_PORT);					// Set server port

	// Create a socket
    SOCKET clientSocket = socket(AF_INET,      // IPv4 address famly
								 SOCK_STREAM,   // Datagram socket
								 IPPROTO_TCP); // UDP protocol

	// Check if socket creation succeeded
    if (clientSocket == INVALID_SOCKET)
    {
        printf("Creating socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

	iResult = connect (clientSocket, (struct sockaddr *)&serverAddress, sockAddrLen);
	if (iResult == SOCKET_ERROR)
	{
		printf("Unable to connect to server\n");
		WSACleanup();
		return 1;
	}
	FILE *file;
	if ( (file = fopen("LoremIpsum.txt", "r")) == NULL)
	{
		printf("Error opening file\n");
		return 1;
	}
	printf("Input offset in bytes:\t");
	scanf("%d", &offset_bytes);
	printf("Input sending duration(length):\t");
	scanf("%d", &send_length);
	send_times = send_length/BUFFER_SIZE + (((send_length % BUFFER_SIZE) != 0) ? 1 : 0); //number of times client sends message
	fseek(file, offset_bytes, SEEK_SET);
	while(i < send_times)
    {	
		if (fgets(dataBuffer, BUFFER_SIZE, file) == NULL) //in case of EOF or error break
			break;
		printf("Pre enkodovanja:%s\n", dataBuffer);
		encode(dataBuffer, BUFFER_SIZE); //encryption
		printf("Posle enkodovanja:%s\n", dataBuffer);
		// Send message to server
		iResult = send(clientSocket, dataBuffer, BUFFER_SIZE, 0);

		// Check if message is succesfully sent. If not, close client application
		if (iResult == SOCKET_ERROR)
		{
			printf("sendto failed with error: %d\n", WSAGetLastError());
			closesocket(clientSocket);
			WSACleanup();
			return 1;
		}
		i++;
	}

	if (fclose(file) == EOF)
	{
		printf("Error closing file\n");
		return 1;
	}

	// Close client application
    iResult = closesocket(clientSocket);
    if (iResult == SOCKET_ERROR)
    {
        printf("closesocket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
        return 1;
    }

	// Close Winsock library
    WSACleanup();

	// Client has succesfully sent a message
    return 0;
}
