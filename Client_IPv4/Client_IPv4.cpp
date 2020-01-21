// UDP client that uses blocking sockets

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "conio.h"
#include <map>
#include <tchar.h>
#include<strsafe.h>

typedef struct thread_params
{
	int offset_bytes, send_length, id;
	int* ports;
}thread_params;

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define SERVER_IP_ADDRESS "127.0.0.1"		// IPv4 address of server
#define SERVER_PORT 27015					// Port number of server that will be used for communication with clients
#define BUFFER_SIZE 512						// Size of buffer that will be used for sending and receiving messages to client
#define MAX_THREADS 5

void encode(char* buff, int buff_size);
void decode(char* buff, int buff_size);
void fill_map();
std::map<int, char> encode_map;
DWORD WINAPI thread_function(LPVOID lp_param);
HANDLE mutex_handle;
FILE *file;
int ports[MAX_THREADS] = {27015, 27016, 27017, 27018, 27019};

int _tmain()
{
	fill_map();
	mutex_handle = CreateMutex( 
        NULL,              // default security attributes
        FALSE,             // initially not owned
        NULL);             // unnamed mutex


	if ( (file = fopen("LoremIpsum.txt", "r")) == NULL)
	{
		printf("Error opening file\n");
		return 1;
	}
	//start thread
	thread_params* data_array[MAX_THREADS];
	DWORD dw_thread_id[MAX_THREADS]; //dword = unsigned 32bit int
	HANDLE h_thread_array[MAX_THREADS];

	for (int i = 0; i < MAX_THREADS; i++)
	{
		data_array[i] = (thread_params*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(thread_params));
		if (data_array[i] == NULL)
			return 1;
		data_array[i]->offset_bytes = i * BUFFER_SIZE;
		data_array[i]->send_length = BUFFER_SIZE;
		data_array[i]->id = i;
		data_array[i]->ports = ports;
		h_thread_array[i] = CreateThread( 
            NULL,                   // default security attributes
            0,                      // use default stack size  
            thread_function,       // thread function name
            data_array[i],          // argument to thread function 
            0,                      // use default creation flags 
            &dw_thread_id[i]);   // returns the thread identifier 

		if (h_thread_array[i] == NULL) //create thread fail check
			return 1;
	}

	//wait for all threads to be done
	WaitForMultipleObjects(MAX_THREADS, h_thread_array, TRUE, INFINITE);

	//close all thread handles and free memory
	for(int i=0; i<MAX_THREADS; i++)
	{
		CloseHandle(h_thread_array[i]);
		if(data_array[i] != NULL)
		{
			HeapFree(GetProcessHeap(), 0, data_array[i]);
			data_array[i] = NULL;    // Ensure address is not reused.
		}
	}
	CloseHandle(mutex_handle);

	//close file
	if (fclose(file) == EOF)
	{
		printf("Error closing file\n");
		return 1;
	}

	// Close Winsock library
    WSACleanup();

	// Client has succesfully sent a message
    return 0;
	//kraj main

}


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

DWORD WINAPI thread_function(LPVOID lp_param)
{
	thread_params* data_array = (thread_params*) lp_param; //getting thread params
	int send_times, i; //variables for sending
	send_times = data_array->send_length/BUFFER_SIZE + (((data_array->send_length % BUFFER_SIZE) != 0) ? 1 : 0); //number of times client sends message
	// Server address structure
    sockaddr_in serverAddress;
    // Size of server address structure
	int sockAddrLen = sizeof(serverAddress);

	// Buffer that will be used for sending and receiving messages to client
    char dataBuffer[BUFFER_SIZE + 1];

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
    serverAddress.sin_port = htons(data_array->ports[data_array->id]);					// Set server port

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
	
	i = 0;
	DWORD wait_result;
	while(i < send_times)
    {
		wait_result = WaitForSingleObject( 
            mutex_handle,    // handle to mutex
            INFINITE);  // no time-out interval

			switch (wait_result)
			{
			case WAIT_OBJECT_0://thread got ownership of the mutex
				__try 
				{
					fseek(file, data_array->offset_bytes, SEEK_SET);
					memset(dataBuffer, 0, sizeof(dataBuffer));
					if (fread(dataBuffer, 1, BUFFER_SIZE, file) == 0) //in case of EOF or error break
						return 1;
					printf("\n-------------------\nDATA_BUFFER:%s\n-------------------\n", dataBuffer);
				}

				__finally 
				{
					if (!ReleaseMutex(mutex_handle))
					{
						printf("Mutex was not released\n");
						return 1;
					}
				}
				break;
			case WAIT_ABANDONED://timeout
				printf("WAIT_ABANDONED\n");
				return 1;
			}
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

	// Close client application
    iResult = closesocket(clientSocket);
    if (iResult == SOCKET_ERROR)
    {
        printf("closesocket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
        return 1;
    }

}