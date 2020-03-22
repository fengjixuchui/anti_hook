#include <cstdio>
#include <iostream>
#include <windows.h>
#include "anti_hook.hpp"

BOOL check_remote_debugger_present_api()
{
	auto b_is_dbg_present = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &b_is_dbg_present);
	return b_is_dbg_present;
}

inline void log()
{
}

template <typename First, typename ...Rest>
void log(First&& message, Rest&&...rest)
{
	std::cout << std::forward<First>(message);
	log(std::forward<Rest>(rest)...);
}

int main()
{
	const auto ntdll = unhook("ntdll.dll");
	if (ntdll == 0)
	{
		log("ntdll restored\r\n");
	}
	else
	{
		log("ntdll fail restored\r\n");
	}
	const auto kernel = unhook("kernel32.dll");
	if (kernel == 0)
	{
		log("kernel32 restored\r\n");
	}
	else
	{
		log("kernel32 fail restored\r\n");
	}
	const auto user32 = unhook("user32.dll");
	if (user32 == 0)
	{
		log("user32 restored\r\n");
	}
	else
	{
		log("user32 fail restored\r\n");
	}
	if (check_remote_debugger_present_api() != FALSE)
	{
		log("CheckRemoteDebuggerPresent detected\r\n");
	}
	getchar();
	return 0;
}
