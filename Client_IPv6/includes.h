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