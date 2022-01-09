#include <Windows.h>
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>
#include <stdio.h>

char* debug_step;
char formatted_message[4097]; // Сюда будет формироваться UDP-пакет для отсылки
char s_date[256];

wchar_t error_string[4096];
extern wchar_t ASL_ServiceName[];

bool flag_IP_initialized=false;
bool flag_IP_error_printed=false;
bool flag_SQL_initialized=false;
bool flag_SQL_error_printed=false;

const char* MON[13]={ "Mit", "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec" };

// Параметры конфигурации
char SERVER_IP[256]={ "127.0.0.1" }; // пока так, потом берётся из файла конфигурации
int PORT=514;	// Порт syslog
int SYSLOG_FORMAT=0;
int MAX_LENGTH=480;
int LOWEST_SEVERITY=6;
int USE_UTC_TIME=0; // Потом будем загружать из файла конфигурации

char HOSTNAME[1024]={ "localhost" };

SOCKET s=0;
struct sockaddr_in si_other; // структура с адресом получателя пакетов
int slen = sizeof(si_other);


//=====================================================================
// Пишем в Application Log
//=====================================================================
//     wType может быть таким:
//     EVENTLOG_SUCCESS
//     EVENTLOG_AUDIT_FAILURE
//     EVENTLOG_AUDIT_SUCCESS
//     EVENTLOG_ERROR_TYPE
//     EVENTLOG_INFORMATION_TYPE
//     EVENTLOG_WARNING_TYPE
//
void WriteEventLogEntry(wchar_t *Message, WORD wType)
{
    HANDLE hEventSource = NULL;
    LPCWSTR lpszStrings[2] ={ NULL, NULL };

    hEventSource = RegisterEventSource(NULL, ASL_ServiceName);
    if (hEventSource)
    {
        lpszStrings[0] = ASL_ServiceName;
        lpszStrings[1] = Message;

        ReportEvent(hEventSource,  // Event log handle
            wType,                 // Event type
            0,                     // Event category
            0,                     // Event identifier
            NULL,                  // No security identifier
            2,                     // Size of lpszStrings array
            0,                     // No binary data
            lpszStrings,           // Array of strings
            NULL                   // No binary data
        );

        DeregisterEventSource(hEventSource);
    }
}

//=====================================================================
// Инициализация работы с сетью
//=====================================================================
int QAS_InitIP()
{
    WSADATA wsa;

    // 0. проверка адреса
    unsigned long ipaddress=inet_addr(SERVER_IP);
    if (INADDR_NONE==ipaddress)
    {
        wsprintf(error_string, L"Bad format of IP address: %hs",SERVER_IP );
        WriteEventLogEntry(error_string, EVENTLOG_ERROR_TYPE);
        return -1;
    }

    // 1. Инициализация winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa))
        return -1;

    // 2. создаём сокет
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
        return -1;

    // 3. заполняем получателя
    //setup address structure
    memset((char*)&si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
    si_other.sin_addr.S_un.S_addr = ipaddress;

    // 4. запомним hostname, пригодится, когда в логе будут пустые поля хостов
    gethostname(HOSTNAME, 1023);

    return 0;
}

SQLHANDLE sqlConnHandle=0;
SQLHANDLE sqlStmtHandle=0;
SQLHANDLE sqlEnvHandle=0;
SQLWCHAR retconstring[1024];

SQLWCHAR    sqlstmt[2048];

SQLBIGINT MAX_ID=0; // Начиная с этой записи нас интересуют сообщения
SQLINTEGER max_id_len=0;
SQLINTEGER MID=0;
SQLINTEGER MID_length=0;

SQLBIGINT id, JobID, jobType;
SQLINTEGER severity, messageID=0, timediff;
TIMESTAMP_STRUCT logUtcTime, logLocalTime;
char messageText[2050], rhostname1[256], rhostname2[256];
SQLINTEGER id_len, severity_len, messageID_len, logUtcTime_len, messageText_len, rhostname1_len, rhostname2_len, logLocalTime_len, JobID_len, jobType_len, timediff_len;

//=====================================================================
// Формирует и посылает
//=====================================================================
void ASL_SyslogFeed()
{
    int PRI,i,l;
    char real_hostname[256];

    // 1. Преобразуем и фильтруем severity
    int syslog_severity=6; // information
    if (severity&2) syslog_severity=4; // warning
    if (severity&4) syslog_severity=3; // error

    if (syslog_severity>LOWEST_SEVERITY) return; // фильтруем ненужную информацию

    PRI=(int)(8+syslog_severity);

    // находим нужное имя хоста по приоритетам: rhostname2, rhostname1, hostname
    if (SQL_NULL_DATA==rhostname2_len)
    {
        if (SQL_NULL_DATA==rhostname1_len)
            strcpy_s(real_hostname, HOSTNAME);
        else
            strcpy_s(real_hostname, rhostname1);
    }
    else
    {
        strcpy_s(real_hostname, rhostname2);
    }
    // если старый формат (RFC3164) обрезаем до без домена
    if (0==SYSLOG_FORMAT)
    {
        l=strlen(real_hostname);
        for (i=0; i<l; i++)
        {
            if ('.'==real_hostname[i])
            {
                real_hostname[i]=0;
                break;
            }
        }
    }

    if (0==SYSLOG_FORMAT) // RFC3164
    {
        sprintf_s(formatted_message, "<%d>%s %2d %02d:%02d:%02d %s job[%lld]: [type:%lld Mesg:%d] %s",
            PRI, MON[logLocalTime.month], logLocalTime.day, logLocalTime.hour, logLocalTime.minute, logLocalTime.second,
            real_hostname, JobID, jobType, messageID, messageText);
    }
    else // RFC5424
    {
        char bias[32]={ "Z" }; // Это если используем UTC

        // Если отказываемся от использования UTC 
        if (!USE_UTC_TIME)
        {
            int h, m;
            char c;

            logUtcTime=logLocalTime;

            // находим, на сколько часов и минут локальное время отличается от utc
            h=timediff/60;
            m=timediff-60*h;
            if (timediff>=0) c='+'; else { c='-'; h=-h; }

            sprintf_s(bias, "%c%02d:%02d", c, h, m);
        }
        

        sprintf_s(formatted_message, "<%d>1 %d-%02d-%02dT%02d:%02d:%02d.%03d%s %s job[%lld]: [type:%lld Mesg:%d] %s",
            PRI, logUtcTime.year, logUtcTime.month, logUtcTime.day, logUtcTime.hour, logUtcTime.minute, logUtcTime.second, logUtcTime.fraction/1000000,
            bias, real_hostname, JobID, jobType, messageID, messageText);
    }

    // ограничиваем длину сообщения
    formatted_message[MAX_LENGTH]=0;

    // в путь!
    sendto(s, formatted_message, strlen(formatted_message), 0, (struct sockaddr*)&si_other, slen);
}

//=====================================================================
// Для служебных сообщений, которые мы пишем сами
//=====================================================================
void syslog_message(int syslog_severity, char *msg)
{
    // Priority 
    int PRI=8+syslog_severity;

    // Время придётся получать самим...
    TIME_ZONE_INFORMATION tzinfo;
    SYSTEMTIME st,lt;

    GetTimeZoneInformation(&tzinfo);
    int timediff=-tzinfo.Bias;

    GetSystemTime(&st);
    GetLocalTime(&lt);

    if (0==SYSLOG_FORMAT) // RFC3164
    {
        sprintf_s(formatted_message, "<%d>%s %2d %02d:%02d:%02d %s ArcUDPsyslog: %s",
            PRI, MON[lt.wMonth], lt.wDay, lt.wHour, lt.wMinute, lt.wSecond,
            HOSTNAME, msg);
    }
    else // RFC5424
    {
        char bias[32]={ "Z" }; // Это если используем UTC

        // Если отказываемся от использования UTC 
        if (!USE_UTC_TIME)
        {
            int h, m;
            char c;

            st=lt;

            // находим, на сколько часов и минут локальное время отличается от utc
            h=timediff/60;
            m=timediff-60*h;
            if (timediff>=0) c='+'; else { c='-'; h=-h; }

            sprintf_s(bias, "%c%02d:%02d", c, h, m);
        }


        sprintf_s(formatted_message, "<%d>1 %d-%02d-%02dT%02d:%02d:%02d.%03d%s %s ArcUDPsyslog: %s",
            PRI, lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds,
            bias, HOSTNAME, msg);
    }

    // ограничиваем длину сообщения
    formatted_message[MAX_LENGTH]=0;

    // в путь!
    sendto(s, formatted_message, strlen(formatted_message), 0, (struct sockaddr*)&si_other, slen);
}

//=====================================================================
// Завершает работу с SQL
//=====================================================================
void HaltSQLSession()
{
    if (sqlStmtHandle)
    {
        SQLFreeStmt(sqlStmtHandle, SQL_CLOSE);
        SQLFreeHandle(SQL_HANDLE_STMT, sqlStmtHandle);
    }
    sqlStmtHandle=0;

    if (sqlConnHandle)
    {
        SQLDisconnect(sqlConnHandle);
        SQLFreeHandle(SQL_HANDLE_DBC, sqlConnHandle);
    }
    sqlConnHandle=0;

    if (sqlEnvHandle)
        SQLFreeHandle(SQL_HANDLE_ENV, sqlEnvHandle);
    sqlEnvHandle=0;

    flag_SQL_initialized=0;
}
//=====================================================================
// Инициализация работы с mssql
//=====================================================================
int QAS_InitSQL()
{
    SQLRETURN result;

    //initializations
    sqlConnHandle = NULL;
    sqlEnvHandle = NULL;

    // 1. allocations
    if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &sqlEnvHandle))
        goto cleanup;

    if (SQL_SUCCESS != SQLSetEnvAttr(sqlEnvHandle, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0))
        goto cleanup;

    if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_DBC, sqlEnvHandle, &sqlConnHandle))
        goto cleanup;

    // 2. соединяемся с сервером
    result=SQLDriverConnect(sqlConnHandle,
        NULL,
        (SQLWCHAR*)L"DRIVER={SQL Server};SERVER=localhost\\ARCSERVE_APP;DATABASE=arcserveUDP;Trusted=true;",
        SQL_NTS,
        retconstring,
        1024,
        NULL,
        SQL_DRIVER_NOPROMPT);

    if (SQL_SUCCESS!=result && SQL_SUCCESS_WITH_INFO!=result)
        goto cleanup;
    
    //if there is a problem connecting then exit application
    if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_STMT, sqlConnHandle, &sqlStmtHandle))
        goto cleanup;

    // 3. При соединении сразу берём максимальный ID и доступность поля MessageID 
    // 3.1. max(id)
    if (SQL_SUCCESS != SQLExecDirect(sqlStmtHandle, (SQLWCHAR*)L"SELECT max(id) from dbo.as_edge_log", SQL_NTS))
        goto cleanup; 

    if (SQL_SUCCESS!=SQLFetch(sqlStmtHandle))
            goto cleanup;
 
    SQLGetData(sqlStmtHandle, 1, SQL_C_SBIGINT, &MAX_ID, 0, &max_id_len);
    SQLFreeStmt(sqlStmtHandle, SQL_CLOSE);

    char debug_msg[256];
    sprintf_s(debug_msg,"Starting to fetch log messages with id>%lld", MAX_ID);
    syslog_message(6, debug_msg);

    // 3.2. наличие поля MessageID в таблице as_edge_log
    if (SQL_SUCCESS != SQLExecDirect(sqlStmtHandle, (SQLWCHAR*)L"SELECT COL_LENGTH('dbo.as_edge_log', 'MessageID')", SQL_NTS))
        goto cleanup;

    if (SQL_SUCCESS!=SQLFetch(sqlStmtHandle))
        goto cleanup;
    SQLGetData(sqlStmtHandle, 1, SQL_INTEGER, &MID, 0, &MID_length);
    SQLFreeStmt(sqlStmtHandle, SQL_CLOSE);

    // 4. Готовим запрос, который будет выполняться каждую 91 секунду
    // формируем запрос в зависимости от того, есть поле MessageID или нет
    wcscpy_s(sqlstmt, L"SELECT l.logUtcTime, l.id, l.messageText, h1.rhostname, h2.rhostname, l.logLocalTime, l.severity, l.JobID, l.jobType, datediff(minute, l.logUtcTime, l.logLocalTime) as timediff ");
    if (SQL_NULL_DATA!=MID_length) wcscat_s(sqlstmt, L", l.messageID ");
    wcscat_s(sqlstmt, L" from dbo.as_edge_log l left join dbo.as_edge_host h1 on l.serverHostId=h1.rhostid left join dbo.as_edge_host h2 on l.targetHostId=h2.rhostid where l.id >? order by l.logUtcTime, l.id");
    
    if (SQL_SUCCESS != SQLPrepare(sqlStmtHandle, sqlstmt, SQL_NTS))
        goto cleanup;

    // привязываем параметр
    if (SQL_SUCCESS != SQLBindParameter(sqlStmtHandle, 1, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0, &MAX_ID, 0, &max_id_len))
        goto cleanup;

    // привязываем возвращаемые переменные
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 1, SQL_C_TIMESTAMP, &logUtcTime, 0, &logUtcTime_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 2, SQL_C_SBIGINT, &id, 0, &id_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 3, SQL_C_CHAR, &messageText, 2050, &messageText_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 4, SQL_C_CHAR, &rhostname1, 255, &rhostname1_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 5, SQL_C_CHAR, &rhostname2, 255, &rhostname2_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 6, SQL_C_TIMESTAMP, &logLocalTime, 0, &logLocalTime_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 7, SQL_INTEGER, &severity, 0, &severity_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 8, SQL_C_SBIGINT, &JobID, 0, &JobID_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 9, SQL_C_SBIGINT, &jobType, 0, &jobType_len)) goto cleanup;
    if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 10, SQL_INTEGER, &timediff, 0, &timediff_len)) goto cleanup;
    
    // Есть ли в таблице MessageID? В UDP версии 6 этого поля не было.
    if(SQL_NULL_DATA!=MID_length)
    { 
        if (SQL_SUCCESS != SQLBindCol(sqlStmtHandle, 11, SQL_INTEGER, &messageID, 0, &messageID_len)) goto cleanup;
    }

    // Усё готово
    return 0;

cleanup:
    HaltSQLSession();
    return -1;
}

//========================================================================================================
// Вызывается каждую 91 секунду, достаёт данные из базы и отсылает в сеть на syslog-сервер
//========================================================================================================
int QueryAndSend()
{
	// 1. Считать конфигурацию, если она не считана

	// 2. Выполнить инициализацию, если не выполнена
    // 2.1. Сеть
    if (!flag_IP_initialized)
    {
        if (QAS_InitIP()) // Это не лечится, тормозим сервис
        {
            return -1;
        }
        else
        {
            flag_IP_initialized=true;

            // Здесь уже можно послать в syslog сообщение о нашем старте
            syslog_message(6, (char *)"ArcUDP syslog feeder version 1.0 started. More information at https://github.com/MastaLomaster/ArcUDPsyslog");
        }
    }

	// 3. Сделать запрос к базе
    if (!flag_SQL_initialized)
    {
        if (QAS_InitSQL())
        {
            if (!flag_SQL_error_printed) // первый раз такое произошло - пишем ошибку
            {
                WriteEventLogEntry((wchar_t *)L"Cannot connect and/or get data from mssql", EVENTLOG_ERROR_TYPE);
                syslog_message(3, (char*)"Cannot connect and/or get data from mssql");
                flag_SQL_error_printed=true;
            }
            return 0; // Может, в следующий раз повезёт.
        }
        else
        {
            if (flag_SQL_error_printed) // соединение восстановлено
            {
                WriteEventLogEntry((wchar_t*)L"Re-connected to mssql", EVENTLOG_INFORMATION_TYPE);
                syslog_message(6, (char*)"Re-connected to mssql");
                flag_SQL_error_printed=false;
            }
            else syslog_message(6, (char*)"Connected to mssql");

            flag_SQL_initialized=true;
        }
    }

    // 4. Возьмём то, что набежало за 91 секунду
    SQLRETURN retcode;
    retcode=SQLExecute(sqlStmtHandle);
    if ((retcode != SQL_SUCCESS) && (retcode != SQL_SUCCESS_WITH_INFO))
    {
        syslog_message(3, (char*)"Cannot fetch data from mssql");
        HaltSQLSession();
        return 0; // Может, в следующий раз повезёт.
    }
    
    while (SQL_SUCCESS == SQLFetch(sqlStmtHandle))
    {
        // 5. Отослать данные на syslog-сервер
        ASL_SyslogFeed();
        MAX_ID=id; // Через 91 секунду будем считывать уже начиная с этого ID
    }

    SQLFreeStmt(sqlStmtHandle, SQL_CLOSE);
    
    return 0;
}

//========================================================================================================
// Отключается от сервера MSSQL, завершает работу с winsock
//========================================================================================================
void QAS_Shutdown()
{
    // 1. Выключаем сессию mssql
    HaltSQLSession();

    // 2. Выключаем сеть
    closesocket(s);
    WSACleanup();
}