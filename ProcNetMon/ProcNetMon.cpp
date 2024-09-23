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

// you can use logman to find this. 
// Microsoft-Windows-TCPIP
//2F07E2EE-15DB-40F1-90EF-9D7BA282188A
DEFINE_GUID(TCPIPProviderGUID, 0x2F07E2EE, 0x15DB, 0x40F1, 0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x8A);

void WINAPI OnEvent(PEVENT_RECORD pEventRecord)
{
	// Get event metadata using TDH API
	int id = pEventRecord->EventHeader.EventDescriptor.Id; 

	//if (id == 1370)
	{
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
					/*
					wprintf(L"\tPropertyName: %ws\n", propertyName);
					wprintf(L"\tLength: %d\n", eventProperty->length);
					wprintf(L"\tInType: %u\n", eventProperty->nonStructType.InType);*/

					switch (eventProperty->nonStructType.InType)
					{
					case 0x0e: // binary data type
					{
						if (wcscmp(propertyName, L"SourceAddress") == 0 ||
							wcscmp(propertyName, L"DestinationAddress") == 0 ||
							wcscmp(propertyName, L"LocalAddress") == 0 ||
							wcscmp(propertyName, L"RemoteAddress") == 0)
						{
							struct sockaddr_in remoteAddr;
							memcpy(&remoteAddr, pPropertyBuffer, sizeof(remoteAddr));

							unsigned short port = ntohs(remoteAddr.sin_port);
							char ipAddress[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &(remoteAddr.sin_addr), ipAddress, INET_ADDRSTRLEN);

							int procId = pEventRecord->EventHeader.ProcessId; 

							wprintf(L"\tPropertyName: %ws\n", propertyName);
							printf("event id: %d, proc id: %d\n", id, procId);
							printf("%s:%d\n", ipAddress, port);
						}
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

void main(void)
{
	EVENT_TRACE_LOGFILEA traceSession; 
	::ZeroMemory(&traceSession, sizeof(traceSession)); 

	LPSTR name = (LPSTR)"dooo"; 

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
