//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>  // For inet_ntoa function
#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <guiddef.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <ws2tcpip.h>
#include <fstream>
#include <map>
#include <string>
#include <iphlpapi.h>

std::map<int, std::string> mp;
int pid = 4064; 

// you can use logman to find this. 
// Microsoft-Windows-TCPIP
//2F07E2EE-15DB-40F1-90EF-9D7BA282188A
DEFINE_GUID(TCPIPProviderGUID, 0x2F07E2EE, 0x15DB, 0x40F1, 0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x8A);

void WINAPI OnEvent(PEVENT_RECORD pEventRecord)
{
	// Get event metadata using TDH API
	int id = pEventRecord->EventHeader.EventDescriptor.Id; 
	int procId = pEventRecord->EventHeader.ProcessId;

	//auto it = mp.find(id);
	//if (it != mp.end()) 
	//{
	//	printf("Event %s\n", it->second); 
	//}	

	//wevtutil gp Microsoft-Windows-TCPIP /ge /gm:true > TcpIpProviderManifest.xml
	// for the ids. 
	if(procId == pid)
	{
		//printf("Event Id: %d\n", id);

		ULONG bufferSize = 0;
		PTRACE_EVENT_INFO pInfo = NULL;
		ULONG status = TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize);
		const DWORD BUF_SIZE = 1024;
		BYTE pPropertyBuffer[BUF_SIZE];

		if (status == ERROR_INSUFFICIENT_BUFFER)
		{
			pInfo = (TRACE_EVENT_INFO*)malloc(bufferSize);
			status = TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize);
		}

		if (pInfo && status == ERROR_SUCCESS)
		{
			for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++)
			{
				auto eventProperty = &pInfo->EventPropertyInfoArray[i];

				auto propertyName = (LPWSTR)((PBYTE)pInfo + eventProperty->NameOffset);
				//wprintf(L"\tPropertyName: %ws\n", propertyName);

				::ZeroMemory(pPropertyBuffer, BUF_SIZE);
				PROPERTY_DATA_DESCRIPTOR propertyDataDesc;
				propertyDataDesc.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
				propertyDataDesc.ArrayIndex = ULONG_MAX;

				auto result = ::TdhGetProperty(
					pEventRecord,
					0,
					NULL,
					1,
					&propertyDataDesc,
					BUF_SIZE,
					pPropertyBuffer);

				if (result == ERROR_SUCCESS)
				{
					//wprintf(L"\tPropertyName: %ws\n", propertyName);
					/*
					wprintf(L"\tPropertyName: %ws\n", propertyName);
					wprintf(L"\tLength: %d\n", eventProperty->length);
					wprintf(L"\tInType: %u\n", eventProperty->nonStructType.InType);*/
					//printf("\tProperty type: %d\n", eventProperty->nonStructType.InType); 
					switch (eventProperty->nonStructType.InType)
					{
					case TDH_INTYPE_BINARY: // binary data type
					{
						//TDH_INTYPE_UINT32
						//if (wcscmp(propertyName, L"SourceAddress") == 0 ||
						//	wcscmp(propertyName, L"DestinationAddress") == 0 ||
						//	wcscmp(propertyName, L"LocalAddress") == 0 ||
						//	wcscmp(propertyName, L"RemoteAddress") == 0)
						//{
						if (id == 1002 || id == 1009 || id == 1003)
						{
							struct sockaddr_in remoteAddr;
							memcpy(&remoteAddr, pPropertyBuffer, sizeof(remoteAddr));

							unsigned short port = ntohs(remoteAddr.sin_port);
							char ipAddress[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &(remoteAddr.sin_addr), ipAddress, INET_ADDRSTRLEN);

							//printf("proc id: %d\n", procId);
							if (id == 1002)
							{
								printf("\t\tTcpRequestConnect %s:%d\n", ipAddress, port);
							}
							else if (id == 1009)
							{
								printf("\t\tTcpCloseEndpoint %s:%d\n", ipAddress, port);
							}
							else if (id == 1003)
							{
								printf("\t\tTcpInspectConnectComplete %s:%d\n", ipAddress, port);
							}
						}

						//}
						break; 
					}
					}
				}
			}
		}

		if (pInfo)
		{
			free(pInfo);
		}
	}
}

DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	// and even more oddly, we now need to call "ProcessTrace" to start the processing. 
	auto response = ::ProcessTrace((PTRACEHANDLE)lpParameter, // the handle
		1, // the number of handles,
		NULL, // start immediately
		NULL // never end
	);
	std::cout << "Finished processing events." << std::endl; 
	return 0; 
}

void StartMonitoring()
{
	EVENT_TRACE_LOGFILEA traceSession;
	::ZeroMemory(&traceSession, sizeof(traceSession));

	LPSTR name = (LPSTR)"duudi";

	// The following defines the session......
	// 
	// this thing has the ability to read from ETL files as well as trace real time. We want real time. 
	traceSession.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	// this is either the session name, or the path of the log file we're reading. 
	traceSession.LoggerName = name;
	// this is the callback. 
	traceSession.EventRecordCallback = (PEVENT_RECORD_CALLBACK)OnEvent;

	// now we're going to initialize structures to start the tracing session. 
	//
	// we're going to heap alloc this, so lets get the size. should be the size of the structure + my name. 
	// the extra char at the end allows for null termination. 
	ULONG tracePropertiesBufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(name) + sizeof(CHAR);
	// heap alloc on local heap. 
	PEVENT_TRACE_PROPERTIES ptrEventTraceProps = (PEVENT_TRACE_PROPERTIES)::LocalAlloc(LPTR, tracePropertiesBufferSize);
	if (ptrEventTraceProps)
	{
		::ZeroMemory(ptrEventTraceProps, tracePropertiesBufferSize);

		// WNODE information. 
		// https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header
		ptrEventTraceProps->Wnode.BufferSize = tracePropertiesBufferSize;
		ptrEventTraceProps->Wnode.ClientContext = 2;
		ptrEventTraceProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

		// EVENT_TRACE_PROPERTIES information. 
		// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
		// https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
		ptrEventTraceProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		ptrEventTraceProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

		// start the tracing session. 
		TRACEHANDLE startTraceHandle;
		auto response = ::StartTraceA(&startTraceHandle, name, ptrEventTraceProps);
		if (response == ERROR_SUCCESS)
		{
			std::cout << "Started tracing successfully" << std::endl;

			// now that we've opened up our tracer, we need to start tracing the thing we want. 
			// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
			response = EnableTraceEx2(
				startTraceHandle, // the handle
				&TCPIPProviderGUID, // provider guid
				EVENT_CONTROL_CODE_ENABLE_PROVIDER, // Update the session configuration so that the session receives the requested events from the provider.
				TRACE_LEVEL_VERBOSE, // limit it to "INFORMATION". 
				NULL, // no keyword match
				NULL, // no additional keyword flags
				0, // zero-latency
				NULL // no other properties. 
			);
			if (response == ERROR_SUCCESS)
			{
				std::cout << "Tcp/IP trace has been enabled." << std::endl;

				// oddly enough, we now need to call "OpenTrace" to start processing events. 
				// i suppose we can think of it as opening the log file, despite it being
				// one we're creating on-the-fly
				TRACEHANDLE openedTraceHandle = ::OpenTraceA(&traceSession);
				if (openedTraceHandle != INVALID_PROCESSTRACE_HANDLE)
				{
					DWORD dwThreadId = 0;
					HANDLE hThread = ::CreateThread(
						NULL,
						0,
						ThreadProc,
						(LPVOID)&openedTraceHandle,
						0,
						&dwThreadId
					);

					if (hThread != INVALID_HANDLE_VALUE)
					{
						std::cout << "Trace opened." << std::endl;

						if (response == ERROR_SUCCESS)
						{
							std::cout << "Press ENTER to stop processing events." << std::endl;
							getchar();

							ControlTrace(
								openedTraceHandle,
								NULL,
								ptrEventTraceProps,
								EVENT_TRACE_CONTROL_STOP);
						}
						else
						{
							std::cout << "Failed to start processing events. Error " << response << std::endl;
						}
					}

					::CloseTrace(openedTraceHandle);
				}
				else
				{
					std::cout << "Failed to open the tracing session. Error " << ::GetLastError() << std::endl;
				}

				// disable the trace. 
				EnableTraceEx2(
					startTraceHandle,
					&TCPIPProviderGUID,
					EVENT_CONTROL_CODE_DISABLE_PROVIDER,
					TRACE_LEVEL_INFORMATION,
					0,
					0,
					0,
					NULL
				);
			}
			else
			{
				std::cout << "Failed to enable a trace. Error " << response << std::endl;
			}

			::StopTraceA(startTraceHandle, name, ptrEventTraceProps);
		}
		else
		{
			std::cout << "Failed to start trace, error " << response << std::endl;
		}

		::LocalFree(ptrEventTraceProps);
	}
}

void ScanCurrent()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
		// Handle error

		PMIB_TCPTABLE_OWNER_PID pTcpTable;

		// call this with null initially to get the structure size we need. 
		DWORD dwNeededSize = 0; 
		auto retVal = GetExtendedTcpTable(
			NULL, // pass null for now. 
			&dwNeededSize, // get back the needed size.
			false, // don't sort
			AF_INET, // ipv4
			TCP_TABLE_OWNER_PID_ALL, // https://learn.microsoft.com/en-us/windows/win32/api/iprtrmib/ne-iprtrmib-tcp_table_class
			0
		); 
		if (retVal == ERROR_INSUFFICIENT_BUFFER)
		{
			pTcpTable = (PMIB_TCPTABLE_OWNER_PID)::HeapAlloc(GetProcessHeap(), 0, dwNeededSize);
			if (pTcpTable)
			{
				retVal = GetExtendedTcpTable(
					pTcpTable, // not null now
					&dwNeededSize, 
					false, // don't sort
					AF_INET, // ipv4
					TCP_TABLE_OWNER_PID_ALL, // https://learn.microsoft.com/en-us/windows/win32/api/iprtrmib/ne-iprtrmib-tcp_table_class
					0
				);
				if (retVal == NO_ERROR)
				{
					for (int i = 0; i < pTcpTable->dwNumEntries; i++)
					{
						auto entry = pTcpTable->table[i]; 
						if (entry.dwOwningPid == pid)
						{
							char szLocalAddr[INET_ADDRSTRLEN]; 
							char szRemoteAddr[INET_ADDRSTRLEN]; 
							struct in_addr addr; 
							addr.S_un.S_addr = entry.dwLocalAddr; 

							auto localPort = ntohs(entry.dwLocalPort);
							inet_ntop(AF_INET, &addr, szLocalAddr, sizeof(szLocalAddr));

							addr.S_un.S_addr = entry.dwRemoteAddr; 
							auto remotePort = ntohs(entry.dwRemotePort); 
							inet_ntop(AF_INET, &addr, szRemoteAddr, sizeof(szRemoteAddr));

							printf("Connected local: %s:%d\n", szLocalAddr, localPort); 
							printf("Connected remote: %s:%d\n", szRemoteAddr, remotePort);
							printf("\n"); 
						}
					}
				}
			}
		}
	}
}


void main(int argc, char* args[])
{
	//std::ifstream input("parsed.txt"); 

	//std::string eventName; 
	//int id; 
	//while (input >> eventName >> id)
	//{
	//	mp.insert(std::pair<int,std::string>(id, eventName.substr(0, eventName.size()-1)));
	//}

	if (argc == 2)
	{
		pid = ::atoi(args[1]); 

		ScanCurrent();
		StartMonitoring();
	}
}
