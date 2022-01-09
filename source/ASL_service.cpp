#include <Windows.h>
#include <stdio.h>
#include <process.h>

// Из файла ASL_InstallConfig.cpp
void ASL_ReadConfig();
// Из файла ASL_QueryAndSend.cpp
void WriteEventLogEntry(wchar_t* Message, WORD wType);
void syslog_message(int syslog_severity, char* msg);

// Функции из файла ASL_QueryAndSend.cpp
int QueryAndSend();
void QAS_Shutdown();

wchar_t ASL_ServiceName[]=L"ArcUDP syslog feeder";
//wchar_t ASL_ServiceDesc[]=L"Feeds syslog with the messages from ArcUDP activity log";

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

static volatile HANDLE hStopWorking=NULL; // Событие с автосбросом
uintptr_t worker_thread_handle=NULL; 

//==================================================
// Здесь выполняется вся грязная работа
//==================================================
unsigned __stdcall ASL_WorkerThread(void* p)
{
	DWORD dwWaitResult;

	WriteEventLogEntry((wchar_t*)L"Starting service", EVENTLOG_INFORMATION_TYPE);

	// здесь прочесть файл конфигурации

	do
	{
		// Здесь будет запрос к базе данных и отсылка в syslog
		if (QueryAndSend()) // теоретически может отказаться работать
		{
			// Сообщаем об остановке через событие
			SetEvent(hStopWorking);
			// Не забываем сообщить об этом SCM
			ServiceStatus.dwWin32ExitCode = 0;
			ServiceStatus.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(hStatus, &ServiceStatus);
		}

		// А потом ждём 91 секунду
		dwWaitResult=WaitForSingleObject(hStopWorking, 91000);
	} 
	while (WAIT_TIMEOUT==dwWaitResult); // Работаем c паузами в 91 секунду, пока не пришло уведомление hStopWorking

	// Завершаем работу с сетью и mssql 
	syslog_message(6, (char*)"ArcUDP syslog feeder is stopping");

	QAS_Shutdown();
	
	WriteEventLogEntry((wchar_t *)L"Stopping service", EVENTLOG_INFORMATION_TYPE);
	
	return 0;
}

//==================================================
// Запускаем рабочий поток
//==================================================
int ASL_StartService()
{
	
	// 1. Событие создадим
	if (!hStopWorking)
	{
		hStopWorking=CreateEvent(0, FALSE, FALSE, 0);
	}

	// 2. Сам поток
	if (!worker_thread_handle)
	{
		worker_thread_handle=_beginthreadex(NULL, 0, ASL_WorkerThread, 0, 0, NULL);
	}

	return 0;
}

//==================================================
// Останавливаем рабочий поток
//==================================================
int ASL_StopService()
{
	// Сообщаем об остановке через событие
	if(hStopWorking) SetEvent(hStopWorking);

	// Ждём завершения в натуре
	if(worker_thread_handle) WaitForSingleObject((HANDLE)worker_thread_handle, INFINITE);
	worker_thread_handle=NULL;

	// Событие тоже прикроем
	if (hStopWorking) CloseHandle(hStopWorking);
	hStopWorking=0;

	return 0;
}

//=====================================================================
// Service Control handler
//=====================================================================
void ASL_ControlHandler(DWORD request)
{
	switch (request)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		ASL_StopService();
		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(hStatus, &ServiceStatus);
		return;

	default:
		break;
	}

	// Report current status
	SetServiceStatus(hStatus, &ServiceStatus);
	return;
}

//=====================================================================
// Service Entry point
//=====================================================================
void WINAPI ASL_ServiceMain(DWORD argc, LPTSTR* argv)
{
	// файл конфигурации читаем ДО старта сервиса
	ASL_ReadConfig();

	// Начинаем с сообщения о стартующем сервисе
	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandler(ASL_ServiceName, (LPHANDLER_FUNCTION)ASL_ControlHandler);
	if (0==hStatus)
	{
		// Registering Control Handler failed
		return;
	}
	
	// Стартуем сервис
	ASL_StartService();

	// We report the running status to SCM. 
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &ServiceStatus);

	// Ждём завершения рабочего потока
	WaitForSingleObject((HANDLE)worker_thread_handle, INFINITE);

	return;
}

//=====================================================================
// Prints usage hints
//=====================================================================
void Usage()
{
	const wchar_t* usage_table[6]=
	{
		L"ArcUDPsyslog.exe is intended to run as the \"ArcUDP syslog feeder\" service\n",
		L"To install the service run \"ArcUDPsyslog.exe -install\"\n",
		L"To uninstall the service run \"ArcUDPsyslog.exe -remove\"\n",
		L"To configure the destination host/port edit the \"ArcUDPsyslog.cfg\" file\n",
		L"More information at https://github.com/MastaLomaster/ArcUDPsyslog\n",
		L"Press any key to continue...\n"
	};

	for (int i=0; i<6; i++)
		fputws(usage_table[i], stderr);

	getchar();
}

//=====================================================================
// Инсталлируем сервис
//=====================================================================
int ASL_Install()
{
	wchar_t binpath[4096]={ L"" };
	GetModuleFileName(NULL, binpath, 4096);

	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hSCManager)
	{
		fputws(L"Can't open Service Control Manager\nMake sure you run the program as Administrator\n", stderr);
		return -1;
	}

	SC_HANDLE hService = CreateService(
		hSCManager,
		ASL_ServiceName,
		ASL_ServiceName,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		binpath,
		NULL, NULL, NULL, NULL, NULL
	);

	if (!hService)
	{
		int err = GetLastError();
		CloseServiceHandle(hSCManager);

		switch (err) // Только популярные ошибки
		{
		case ERROR_ACCESS_DENIED:
			fputws(L"ERROR_ACCESS_DENIED\n Make sure you run the program as Administrator\n", stderr);
			break;
		case ERROR_DUPLICATE_SERVICE_NAME:
			fputws(L"ERROR_DUPLICATE_SERVICE_NAME\n", stderr);
			break;
		case ERROR_INVALID_NAME:
			fputws(L"ERROR_INVALID_NAME\n", stderr);
			break;
		case ERROR_SERVICE_EXISTS:
			fputws(L"ERROR_SERVICE_EXISTS\n", stderr);
			break;
		}
		fputws(L"Failed to create ArcUDP syslog feeder service\n", stderr);
		return -1;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	fputws(L"ArcUDP syslog feeder service successfully installed\n", stderr);

	return 0;
}

//=====================================================================
// Инсталлируем сервис
//=====================================================================
int ASL_Remove()
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hSCManager)
	{
		fputws(L"Can't open Service Control Manager\nMake sure you run the program as Administrator\n", stderr);
		return -1;
	}

	SC_HANDLE hService = OpenService(hSCManager, ASL_ServiceName, SERVICE_STOP | DELETE);
	if (!hService) 
	{
		fputws(L"Can't remove ArcUDP syslog feeder service\n", stderr);
		CloseServiceHandle(hSCManager);
		return -1;
	}

	DeleteService(hService);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	fputws(L"ArcUDP syslog feeder service successfully removed\n", stderr);

	return 0;
}

//=====================================================================
// Executable entry point
//=====================================================================
int wmain(int argc, wchar_t* argv[]) 
{
	// мы работаем только с одним сервисом
	SERVICE_TABLE_ENTRY ServiceTable[2]=
	{
		{ ASL_ServiceName, &ASL_ServiceMain },
		{ NULL, NULL }
	};

	if (!StartServiceCtrlDispatcher(ServiceTable)) // К бабке не ходи - ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
	{
		if (2==argc)
		{
			if (0==wcscmp(argv[1], L"-install")) return ASL_Install();
			if (0==wcscmp(argv[1], L"-remove")) return ASL_Remove();
		}
		
		// Памятка про способы использования
		Usage();
	}

	
}




