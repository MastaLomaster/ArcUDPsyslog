#include <Windows.h>
#include <stdio.h>

// функция из файла ASL_QueryAndSend.cpp
void WriteEventLogEntry(wchar_t* Message, WORD wType);

// параметры конфигурации
extern char SERVER_IP[256];
extern int PORT;
extern int SYSLOG_FORMAT;
extern int MAX_LENGTH;
extern int LOWEST_SEVERITY;
extern int USE_UTC_TIME;

static wchar_t current_dir[4096]={ L"" };
static char char_buf[4096]={ "" };

//===========================================================================================
// Читаем файл конфигурации
//===========================================================================================
void ASL_ReadConfig()
{
	FILE* fin=NULL;

	int i, len;

	// 1. Получим имя файла конфигурации вместе с каталогом
	GetModuleFileName(NULL, (wchar_t*)current_dir, 4093);
	len=wcslen(current_dir);

	// Ищем последний обратный слеш и заменяем его на 0 (конец строки)
	for (i=len-1; i>=0; i--)
	{
		if (L'\\'==current_dir[i])
		{
			current_dir[i]=0;
			break;
		}
	}

	// добавляем "\\ArcUDPsyslog.cfg"
	wcscat_s(current_dir, L"\\ArcUDPsyslog.cfg");

	// 2. Открываем файл
	_wfopen_s(&fin, current_dir, L"r");

	if (NULL==fin)
	{
		WriteEventLogEntry((wchar_t*)L"Failed to read config file, using default values (127.0.0.1:514)", EVENTLOG_INFORMATION_TYPE);
		return;
	}

	// 3. перебираем все строки и ищем параметры
	while (fgets(char_buf, 4093, fin))
	{
		// делаем строку конфигурации нечувствительной к регистру
		len=strlen(char_buf);
		for (i=0; i<len; i++)
			char_buf[i]=(char)toupper(char_buf[i]);
		
		if (('#'==char_buf[0])||('\n'==char_buf[0])) continue; // пропускаем закомментированные и пустые строки

		sscanf_s(char_buf, "PORT %d", &PORT);
		sscanf_s(char_buf, "SERVER_IP %s", &SERVER_IP, 255);
		sscanf_s(char_buf, "SYSLOG_FORMAT %d", &SYSLOG_FORMAT);
		sscanf_s(char_buf, "MAX_LENGTH %d", &MAX_LENGTH);
		sscanf_s(char_buf, "LOWEST_SEVERITY %d", &LOWEST_SEVERITY);
		sscanf_s(char_buf, "USE_UTC_TIME %d", &USE_UTC_TIME);
	}

	// подчищаем неправильные параметры
	if ((SYSLOG_FORMAT<0)||(SYSLOG_FORMAT>1)) SYSLOG_FORMAT=0;
	if ((MAX_LENGTH<480)||(MAX_LENGTH>4000)) MAX_LENGTH=480;
	if ((LOWEST_SEVERITY>6)||(LOWEST_SEVERITY<3)) LOWEST_SEVERITY=6;

	// 4. закрываем файл
	fclose(fin);
}

void ASL_Install()
{

}