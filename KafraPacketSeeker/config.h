#pragma once

#define USE_CONSOLE_LOG

#define HOOK_SEND
//#define HOOK_BOTH





#if !defined USE_CONSOLE_LOG
#define USE_TXT_LOG
#endif
#if !defined HOOK_SEND
	#define HOOK_RECEIVED
#endif

#if defined HOOK_BOTH
#undef HOOK_SEND
#undef HOOK_RECEIVED
#endif