// UDP server that use blocking sockets

#define WIN32_LEAN_AND_MEAN

#include "includes.h"
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define SERVER_PORT 27015	// Port number of server that will be used for communication with clients
#define BUFFER_SIZE 512		// Size of buffer that will be used for sending and receiving messages to clients
#define MAX_THREADS 5
void encode(char* buff, int buff_size);
void decode(char* buff, int buff_size);
void fill_map();
DWORD WINAPI thread_function(LPVOID lp_param);

// Checks if ip address belongs to IPv4 address family
bool is_ipV4_address(sockaddr_in6 address);
std::map<int, char> encode_map;
FILE* file;
int ports[PORTS] = {27015, 27016, 27017, 27018, 27019};
HANDLE mutex_handle;
int _tmain()
{
	fill_map(); //encoding map

	mutex_handle = CreateMutex( 
        NULL,              // default security attributes
        FALSE,             // initially not owned
        NULL);             // unnamed mutex

	if (mutex_handle == NULL)
	{
		printf("Create mutex error: %d\n", GetLastError());
		return 1;
	}

	if ((file = fopen("Recieved_Messages.txt", "w")) == NULL)
	{
		printf("Error opening file\n");
		return 1;
	}
	thread_params* data_array[MAX_THREADS];
	DWORD dw_thread_id[MAX_THREADS]; //dword = unsigned 32bit int
	HANDLE h_thread_array[MAX_THREADS]; //

	for (int i = 0; i < MAX_THREADS; i++)
	{
		data_array[i] = (thread_params*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(thread_params));
		if (data_array[i] == NULL)
			return 1;

		data_array[i]->ports = ports;
		data_array[i]->id = i;
		data_array[i]->offset_bytes = i * BUFFER_SIZE;

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
	return 0;
}

bool is_ipV4_address(sockaddr_in6 address)
{
	char *check = (char*)&address.sin6_addr.u;

	for (int i = 0; i < 10; i++)
		if(check[i] != 0)
			return false;
		
	if(check[10] != -1 || check[11] != -1)
		return false;

	return true;
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
	thread_params* data_array = (thread_params*) lp_param;
	// Server address 
     sockaddr_in6  serverAddress;
	 sockaddr_in ipv4_server_Address;

	// Buffer we will use to send and receive clients' messages
    char dataBuffer[BUFFER_SIZE];

	// WSADATA data structure that is to receive details of the Windows Sockets implementation
    WSADATA wsaData;

	// Initialize windows sockets library for this process
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
    {
        printf("WSAStartup failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    // Initialize serverAddress structure used by bind function
	memset((char*)&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin6_family = AF_INET6; 			// set server address protocol family
    serverAddress.sin6_addr = in6addr_any;			// use all available addresses of server
	serverAddress.sin6_port = htons(data_array->ports[data_array->id]);	// Set server port
	serverAddress.sin6_flowinfo = 0;				// flow info

    // Create a socket 
    SOCKET ipv6_listen_socket = socket(AF_INET6,      // IPv6 address famly
								 SOCK_STREAM,   // stream socket
								 IPPROTO_TCP); // TCP


	SOCKET ipv6_client_socket;
	// Check if socket creation succeeded
    if (ipv6_listen_socket == INVALID_SOCKET)
    {
        printf("Creating socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
	
	// Disable receiving only IPv6 packets. We want to receive both IPv4 and IPv6 packets.
	char no[4] = {0};
	int ipv6_Result = setsockopt(ipv6_listen_socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)no, sizeof(no));
	int ipv4_Result;
	if (ipv6_Result == SOCKET_ERROR) 
			printf("failed with error: %u\n", WSAGetLastError());

    // Bind server address structure (type, port number and local address) to socket
    ipv6_Result = bind(ipv6_listen_socket,(SOCKADDR *)&serverAddress, sizeof(serverAddress));
	// Check if socket is succesfully binded to server datas

    if (ipv6_Result == SOCKET_ERROR)
    {
        printf("Socket bind failed with error: %d\n", WSAGetLastError());
        closesocket(ipv6_listen_socket);
        WSACleanup();
        return 1;
    }
	
	//printf("Simple TCP server waiting for client messages.\n");
	ipv6_Result = listen(ipv6_listen_socket, SOMAXCONN);
	

	if (ipv6_Result == SOCKET_ERROR)
	{
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ipv6_listen_socket);
        WSACleanup();
        return 1;
	}
	sockaddr_in6 clientAddress;
	memset(&clientAddress, 0, sizeof(clientAddress));
	int sockAddrLen = sizeof(clientAddress);
	ipv6_client_socket = accept(ipv6_listen_socket, (struct sockaddr *)&clientAddress, &sockAddrLen);
    if (ipv6_client_socket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ipv6_listen_socket);
        WSACleanup();
        return 1;
    }

	closesocket(ipv6_listen_socket);
    // Main server loop
    do
    {
		// Set whole buffer to zero
        memset(dataBuffer, 0, BUFFER_SIZE);
		// Receive client message
        ipv6_Result = recv(ipv6_client_socket, dataBuffer, BUFFER_SIZE, 0);
		
		// Check if message is succesfully received
		if (ipv6_Result == SOCKET_ERROR)
		{
			printf("recvfrom failed with error: %d\n", WSAGetLastError());
			break;
		}

		decode(dataBuffer, BUFFER_SIZE); //decryption
		printf("offset_bytes:%d\n", data_array->offset_bytes);

		DWORD count = 0, wait_result;

		while (count < 20)
		{
			wait_result = WaitForSingleObject( 
            mutex_handle,    // handle to mutex
            INFINITE);  // no time-out interval

			switch (wait_result)
			{
			case WAIT_OBJECT_0://thread got ownership of the mutex
				__try {
					fseek(file, data_array->offset_bytes, SEEK_SET);//moving to correct location
					if (fwrite(dataBuffer, sizeof(char), BUFFER_SIZE, file) != BUFFER_SIZE)
					{
						printf("Error writing in file\n");
						return 1;
					}
					count++;
				}

				__finally {
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
		}
        char ipAddress[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN 65 spaces for hexadecimal notation of IPv6
		
		// Copy client ip to local char[]
		inet_ntop(clientAddress.sin6_family, &clientAddress.sin6_addr, ipAddress, sizeof(ipAddress));
        
		// Convert port number from network byte order to host byte order
        unsigned short clientPort = ntohs(clientAddress.sin6_port);

		bool isIPv4 = is_ipV4_address(clientAddress); //true for IPv4 and false for IPv6

		if(isIPv4){
			char ipAddress1[15]; // 15 spaces for decimal notation (for example: "192.168.100.200") + '\0'
			struct in_addr *ipv4 = (struct in_addr*)&((char*)&clientAddress.sin6_addr.u)[12]; 
			
			// Copy client ip to local char[]
			strcpy_s(ipAddress1, sizeof(ipAddress1), inet_ntoa( *ipv4 ));
			printf("IPv4 Client connected from ip: %s, port: %d, sent: %s.\n---------------\n", ipAddress1, clientPort, dataBuffer);
		}else
			printf("IPv6 Client connected from ip: %s, port: %d, sent: %s.\n---------------\n", ipAddress, clientPort, dataBuffer);
		
		// Possible server-shutdown logic could be put here
    }while (ipv6_Result > 0);

    // Close server application
    ipv6_Result = closesocket(ipv6_client_socket);
    if (ipv6_Result == SOCKET_ERROR)
    {
        printf("closesocket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
        return 1;
    }
	printf("Connection successfully shut down.\n");
}