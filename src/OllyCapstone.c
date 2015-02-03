#define ISOLATION_AWARE_ENABLED 1 /* Visual Style Support*/
#include <Windows.h>
#include <commctrl.h>
#pragma warning (disable:4201)
#include "Plugin.h"
#pragma warning (default:4201)

#include <capstone.h>
#include "resource.h"
#include "version.h"

#define OLLY_ACPUASM			(0xcd6a4)
#define OLLY_DISASM_LOWERCASE	(0xd9170)

typedef void (cdecl *FP_ADDTOLIST)(long addr,int highlight,char *format,...);
typedef int  (cdecl *FP_PLUGINWRITEINTTOINI)(HINSTANCE dllinst,char *key,int value);
typedef int  (cdecl *FP_PLUGINREADINTFROMINI)(HINSTANCE dllinst,char *key,int def);

FP_ADDTOLIST			fpAddToList = NULL;
FP_PLUGINWRITEINTTOINI  fpPluginwriteinttoini = NULL;
FP_PLUGINREADINTFROMINI fpPluginreadintfromini = NULL;

HMODULE g_hDllModule        = NULL;
HWND    g_hOllyMainWnd      = NULL;
HMODULE g_hOlly             = NULL;
BOOL   *g_pDisasmLowercase  = NULL;
HWND   *g_hOllyACPUASM      = NULL;

#define OLLY_CAPSTONE_MODE_KEY			("Enabled")
#define OLLY_CAPSTONE_MODE_SYNTAX		("Syntax")
#define OLLY_CAPSTONE_MODE_DEFAULT		(1)
#define OLLY_CAPSTONE_MODE_SYNTAX_INTEL (1)
#define OLLY_CAPSTONE_MODE_SYNTAX_ATT   (2)

/* Capstone */
csh     g_cshHandle = 0;

/* hook */
DWORD_PTR g_DisasmOriginalAddr = 0;
BYTE      g_SavedBytes[5];

/* Config*/
int    g_EnableOllyCapstone = 0;
int    g_Syntax = OLLY_CAPSTONE_MODE_SYNTAX_INTEL;

/************************************************************************/
/*                     Olly Helper                                      */
/************************************************************************/

BOOL InitOllyEnvironment(void)
{
	if (g_hOlly == NULL)
		return FALSE;

	fpAddToList = (FP_ADDTOLIST)(GetProcAddress(g_hOlly, "_Addtolist"));
	fpPluginwriteinttoini = (FP_PLUGINWRITEINTTOINI)(GetProcAddress(g_hOlly, 
									"_Pluginwriteinttoini"));
	fpPluginreadintfromini = (FP_PLUGINREADINTFROMINI)(GetProcAddress(g_hOlly, 
									"_Pluginreadintfromini"));

	g_pDisasmLowercase = (BOOL *)((DWORD_PTR)g_hOlly + OLLY_DISASM_LOWERCASE);
	g_hOllyACPUASM     = (HWND *)((DWORD_PTR)g_hOlly + OLLY_ACPUASM);

	if (!fpAddToList || 
		!fpPluginwriteinttoini || 
		!fpPluginreadintfromini)
		return FALSE;

	return TRUE;
}

BOOL UpdateAsmWnd(void)
{
	HWND hOllyACPUASM = *g_hOllyACPUASM;

	if (g_cshHandle)
	{
		switch(g_Syntax)
		{
		case OLLY_CAPSTONE_MODE_SYNTAX_INTEL:
			cs_option(g_cshHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
			break;
			
		case OLLY_CAPSTONE_MODE_SYNTAX_ATT:
			cs_option(g_cshHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
			break;
			
		default:
			break;
		}
	}
	if (!hOllyACPUASM)
		return FALSE;

	if (!InvalidateRect(hOllyACPUASM, NULL, TRUE))
		return FALSE;
	return UpdateWindow(hOllyACPUASM);
}

/************************************************************************/
/*                   Option Dialog                                      */
/************************************************************************/
/* Enable or disable controls inside the groupbox based on the checkbox state.*/
void CheckGroup(__in HWND hwnd, __in int idCheckbox, __in int idGroupbox)
{
	LRESULT nCheck = SendDlgItemMessage(hwnd, idCheckbox, BM_GETCHECK, 0, 0);
	HWND    hwndGroup    = GetDlgItem(hwnd, idGroupbox);
	HWND    hwndCheckbox = GetDlgItem(hwnd, idCheckbox);
	RECT    rcGroupbox, rcWnd, rcTest;
	HWND    hwndChild;

	if (!GetWindowRect(hwndGroup, &rcGroupbox))
		return;

	/* Get first child control */
	hwndChild = GetWindow(hwnd, GW_CHILD);
	while(hwndChild)
	{
		if (hwndGroup != hwndChild && hwndChild != hwndCheckbox)
		{
			if (GetWindowRect(hwndChild, &rcWnd))
			{
				if (IntersectRect(&rcTest, &rcGroupbox, &rcWnd))
					EnableWindow(hwndChild, nCheck == BST_CHECKED);
			}					
		}
		hwndChild = GetWindow(hwndChild, GW_HWNDNEXT);
	}
}

void InitCheckGroup(__in HWND hwnd, __in int idCheckbox, __in int idGroupbox)
{
	RECT    rc;
	HWND    hwndCheckbox= GetDlgItem(hwnd, idCheckbox);
	HWND    hwndGroup = GetDlgItem(hwnd, idGroupbox);
	POINT   newCheckboxPlace;

	/* Clear the groupbox text */
	SetDlgItemText(hwnd, idGroupbox, TEXT(""));
	
	/* get groupbox coordinates */
	GetWindowRect(hwndGroup, &rc);
	newCheckboxPlace.x = rc.left;
	newCheckboxPlace.y = rc.top;
	ScreenToClient(hwnd, &newCheckboxPlace);
	GetClientRect(hwndCheckbox, &rc);	

	// Move the checkbox on top of the groupbox
	SetWindowPos(hwndCheckbox, hwndGroup, 
		newCheckboxPlace.x+8, newCheckboxPlace.y, 
		rc.right, rc.bottom, 
		0);
	CheckGroup(hwnd, idCheckbox, idGroupbox);
}

INT_PTR CALLBACK OptionDialogProc(__in HWND hwndDlg, __in UINT uMsg, __in WPARAM wParam, __in LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		/* initialize check box*/
		SendDlgItemMessage(hwndDlg, IDC_CHK_ENABLE, 
			BM_SETCHECK, 
			g_EnableOllyCapstone ? BST_CHECKED : BST_UNCHECKED, 0);
		SendDlgItemMessage(hwndDlg, IDC_CHK_DISASSEMBLE_IN_LOWERCASE, 
			BM_SETCHECK, 
			*g_pDisasmLowercase ? BST_CHECKED : BST_UNCHECKED, 0);
		InitCheckGroup(hwndDlg, IDC_CHK_ENABLE, IDC_SYNTAX);

		/* Initialize radio buttons */
		switch(g_Syntax)
		{
		case OLLY_CAPSTONE_MODE_SYNTAX_INTEL:
			SendDlgItemMessage(hwndDlg, IDC_RD_INTEL, BM_SETCHECK, BST_CHECKED, 0);
			break;
		case OLLY_CAPSTONE_MODE_SYNTAX_ATT:
			SendDlgItemMessage(hwndDlg, IDC_RD_ATT, BM_SETCHECK, BST_CHECKED, 0);
			break;
		}

		break;

	case WM_COMMAND:
		switch(wParam)
		{
		case IDC_CHK_ENABLE: /* "Enable" checkbox */
			g_EnableOllyCapstone = (BST_CHECKED == 
				SendDlgItemMessage(hwndDlg, IDC_CHK_ENABLE, BM_GETCHECK, 0, 0));
			CheckGroup(hwndDlg, IDC_CHK_ENABLE, IDC_SYNTAX);
			UpdateAsmWnd(); 
			break;

		case IDC_CHK_DISASSEMBLE_IN_LOWERCASE: /* "Lowercase" checkbox */
			*g_pDisasmLowercase = (BST_CHECKED == 
				SendDlgItemMessage(hwndDlg, IDC_CHK_DISASSEMBLE_IN_LOWERCASE, BM_GETCHECK, 0, 0));
			UpdateAsmWnd(); 
			break;

		case IDC_RD_ATT:
			if (BST_CHECKED == SendDlgItemMessage(hwndDlg, IDC_RD_ATT, BM_GETCHECK, 0, 0))
			{
				g_Syntax = OLLY_CAPSTONE_MODE_SYNTAX_ATT;
				UpdateAsmWnd();
			}
			break;

		case IDC_RD_INTEL:
			if (BST_CHECKED == SendDlgItemMessage(hwndDlg, IDC_RD_INTEL, BM_GETCHECK, 0, 0))
			{
				g_Syntax = OLLY_CAPSTONE_MODE_SYNTAX_INTEL;
				UpdateAsmWnd();
			}
			break;

		case IDCANCEL: /*press ESC*/
		case IDC_BTN_CLOSE: /* click "Close" button */
			PostMessage(hwndDlg, WM_CLOSE, 0, 0);
			break;

		default:
			return FALSE;
		}
		break;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		break;

	default:
		return FALSE;
	}
	
	return TRUE;
}

INT_PTR CALLBACK AboutDialogProc(__in HWND hwndDlg, __in UINT uMsg, __in WPARAM wParam, __in LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_COMMAND:
		switch(wParam)
		{
		case IDCANCEL:
		case IDOK:
			PostMessage(hwndDlg, WM_CLOSE, 0, 0);
			break;
		default:
			return FALSE;
		}
		break;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		break;

	default:
		return FALSE;
	}

	return TRUE;
}

/************************************************************************/
/*                     new disasm function                              */
/************************************************************************/
ulong cdecl NewDisasm(ulong nOldDisasmSize, uchar *src, ulong srcsize,
					  ulong srcip, uchar *srcdec,
					  t_disasm *disasm,int disasmmode,ulong threadid)
{
	uint16_t i;
	unsigned int j;
	cs_insn *insn;
	size_t count;
	char base_str_lowercase[] = "0123456789abcdef";
	char base_str_uppercase[] = "0123456789ABCDEF";
	char *p;
	ulong nsize = nOldDisasmSize;

	if (g_EnableOllyCapstone == 0)
		return nsize;

	if (*g_pDisasmLowercase)
		p = base_str_lowercase;
	else
		p = base_str_uppercase;

	count = cs_disasm(g_cshHandle, src, srcsize, srcip, 1, &insn);
	if (count != 1)
	{
		
		fpAddToList(0, 1, "[%s error] cs_disasm(): %s.", OLLY_CAPSTONE_NAME, 
			cs_strerror(cs_errno(g_cshHandle)));
		
		return nsize; /*using result from Olly */
	}
	else
	{
		if (disasm == NULL)
		{
			cs_free(insn, count);
			return nsize;
		}

		switch(disasmmode & DISASM_MODE) /* extract disassembling mode */
		{
		case DISASM_DATA:
		case DISASM_TRACE:
		case DISASM_FILE:
		case DISASM_CODE:
		case DISASM_ALL:
		case DISASM_RTRACE:

			for (j = 0, i = 0; i < insn->size && j < TEXTLEN-2; ++i)
			{
				disasm->dump[j++] = p[insn->bytes[i] >> 4 ];
				disasm->dump[j++] = p[insn->bytes[i] & 0xf];
			}
			disasm->dump[j] = '\0';

			strcpy_s(disasm->result, TEXTLEN, insn->mnemonic);
			strcat_s(disasm->result, TEXTLEN, " ");
			strcat_s(disasm->result, TEXTLEN, insn->op_str);

			if (!(*g_pDisasmLowercase))
			{
				p = disasm->result;
				while (*p)
					*p++ = (char)toupper(*p);
			}

		case DISASM_SIZE: /* Determine command size only */
			nsize = insn->size;
			break;
		default:
			break;
		}

		cs_free(insn, count);
	}

	return nsize;
}

__declspec (naked) void DisasmTrampoline(void)
{
	/* original bytes
	__asm
	{
	push ebp
	mov  ebp, esp
	add  esp, -738h
	jmp  DWORD PTR [g_DisasmOriginalAddr]
	}*/

	__asm
	{
		push ebp 
		mov  ebp, esp

		/* call the original _Disasm function */
		push  dword ptr [ebp + 0x20] /* threadid   */
		push  dword ptr [ebp + 0x1c] /* disasmmode */
		push  dword ptr [ebp + 0x18] /* disasm     */
		push  dword ptr [ebp + 0x14] /* srcdec     */
		push  dword ptr [ebp + 0x10] /* srcip      */
		push  dword ptr [ebp + 0x0c] /* srcsize    */
		push  dword ptr [ebp + 0x08] /* src        */
		push  offset NEWDISASM_BEGIN
		push  ebp
		mov   ebp, esp
		add   esp, -0x738
		mov   eax, DWORD PTR [g_DisasmOriginalAddr]
		jmp   eax

NEWDISASM_BEGIN:
		push  eax /* command size which is determined by Olly */
		call  NewDisasm
		add   esp, 0x20
		pop   ebp
		retn
	}
}

extc int _export cdecl ODBG_Plugindata(char shortname[32]) 
{
	strcpy_s(shortname, 32, OLLY_CAPSTONE_NAME); /* Name of plugin */
	return PLUGIN_VERSION;
}

void LoadConfig( void )
{
	g_EnableOllyCapstone = fpPluginreadintfromini(g_hDllModule, 
		OLLY_CAPSTONE_MODE_KEY, OLLY_CAPSTONE_MODE_DEFAULT);

	g_EnableOllyCapstone = g_EnableOllyCapstone ? 1 : 0;

	g_Syntax = fpPluginreadintfromini(g_hDllModule, 
		OLLY_CAPSTONE_MODE_SYNTAX, OLLY_CAPSTONE_MODE_SYNTAX_INTEL);

	switch(g_Syntax)
	{
	case OLLY_CAPSTONE_MODE_SYNTAX_INTEL:
	case OLLY_CAPSTONE_MODE_SYNTAX_ATT:
		break;

	default:
		g_Syntax = OLLY_CAPSTONE_MODE_SYNTAX_INTEL;
		break;
	}
}

extc int _export cdecl ODBG_Plugininit(int ollydbgversion, HWND hw, ulong *features) 
{
	DWORD_PTR disasmAddr = 0;
	DWORD fOldProtect = 0;
	unsigned int i;
	UNREFERENCED_PARAMETER(features);

	/* compatibility with v1.10. */
	if (ollydbgversion != PLUGIN_VERSION) 
		return -1;

	if (!InitOllyEnvironment())
		return -1;

	/* Load configuration from file and verify values */
	LoadConfig();

	/* Initialize Capstone */
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &g_cshHandle) != CS_ERR_OK)
		return -1;

	/* Enable syntax */
	switch(g_Syntax)
	{
	case OLLY_CAPSTONE_MODE_SYNTAX_INTEL:
		cs_option(g_cshHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
		break;
		
	case OLLY_CAPSTONE_MODE_SYNTAX_ATT:
		cs_option(g_cshHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		break;
		
	default:
		break;
	}

	cs_option(g_cshHandle, CS_OPT_DETAIL, CS_OPT_ON);

	g_hOllyMainWnd = hw;

	/* Hook Disasm function */
	disasmAddr = (DWORD_PTR)GetProcAddress(g_hOlly, "_Disasm");
	if (!disasmAddr)
	{
		cs_close(&g_cshHandle);
		return -1; /* fail to load _Disasm */
	}
	
	if (!VirtualProtect((LPVOID)disasmAddr, 0x200, PAGE_EXECUTE_READWRITE, &fOldProtect))
	{
		cs_close(&g_cshHandle);
		return -1;
	}

	for (i = 0; i < sizeof(g_SavedBytes); ++i)
	{
		g_SavedBytes[i] = *(BYTE*)(disasmAddr + i);
	}
	
	*(DWORD_PTR*)((BYTE*)disasmAddr + 1) = (DWORD_PTR)DisasmTrampoline - (disasmAddr + 5);
	*(BYTE*)disasmAddr = (BYTE)0xe9;
	g_DisasmOriginalAddr = disasmAddr + 9;

	VirtualProtect((LPVOID)disasmAddr, 0x200, fOldProtect, &fOldProtect);

	/* Plugin successfully initialized. Now is the best time to report this fact
	to the log window. */
	fpAddToList(0, 0, "%s plugin version %d.%d", 
		OLLY_CAPSTONE_NAME, 
		OLLY_CAPSTONE_MAJOR_VERSION, OLLY_CAPSTONE_MINOR_VERSION);

	return 0;
}

/* Function adds items either to main OllyDbg menu (origin=PM_MAIN) or to popup
menu in one of standard OllyDbg windows. */
extc int _export cdecl ODBG_Pluginmenu(int origin, char data[4096], void *item) 
{
	UNREFERENCED_PARAMETER(item);

	if (origin == PM_MAIN)
	{
		strcpy_s(data, 4096, "0 &Options|1 &About");
		return 1;
	}
	return 0;
}

/* This optional function receives commands from plugin menu in window of type origin. */
extc void _export cdecl ODBG_Pluginaction(int origin, int action, void *item) 
{
	UNREFERENCED_PARAMETER(item);

	if ( origin == PM_MAIN ) 
	{
		switch (action) 
		{
		case 0:
		    /* show "Options" dialog */
			DialogBoxParam((HINSTANCE)g_hDllModule, MAKEINTRESOURCE(IDD_OPTIONS), 
				g_hOllyMainWnd, OptionDialogProc, 0);
			break;

		case 1:
			/* About */
			DialogBoxParam((HINSTANCE)g_hDllModule, MAKEINTRESOURCE(IDD_ABOUT), 
				g_hOllyMainWnd, AboutDialogProc, 0);
			break;

		default: 
			break;
		}
	}
}

/* Function is called when user opens new or restarts current application. */
extc void _export cdecl ODBG_Pluginreset(void) 
{
}

/* OllyDbg calls this optional function when user wants to terminate OllyDbg. */
extc int _export cdecl ODBG_Pluginclose(void) 
{
	fpPluginwriteinttoini(g_hDllModule, 
		OLLY_CAPSTONE_MODE_KEY, g_EnableOllyCapstone);

	fpPluginwriteinttoini(g_hDllModule, 
		OLLY_CAPSTONE_MODE_SYNTAX, g_Syntax);
	return 0;
}

/* OllyDbg calls this optional function once on exit. */
extc void _export cdecl ODBG_Plugindestroy(void) 
{
	/* Unhook */
	unsigned int i = 0;
	DWORD_PTR disasmAddr = 0;
	DWORD fOldProtect = 0;
	disasmAddr = (DWORD_PTR)GetProcAddress(g_hOlly, "_Disasm");
	if (disasmAddr)
	{
		if (VirtualProtect((LPVOID)disasmAddr, 0x200, PAGE_READWRITE, &fOldProtect))
		{
			for (i = 0; i < sizeof(g_SavedBytes); ++i)
			{
				*(BYTE*)(disasmAddr + i) = g_SavedBytes[i];
			}

			VirtualProtect((LPVOID)disasmAddr, 0x200, fOldProtect, &fOldProtect);
		}
	}

	cs_close(&g_cshHandle);
}

BOOL APIENTRY DllMain( __in HMODULE hDllModule, __in DWORD dwReason, __in LPVOID reserved) 
{
	UNREFERENCED_PARAMETER(reserved);

	switch(dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hDllModule);
		g_hDllModule = hDllModule;
		g_hOlly = GetModuleHandle(NULL);
		break;

	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE; 
}
