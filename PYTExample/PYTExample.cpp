#include <iostream>
#include "auth.hpp"
#include "Encryption/skStr.h"
#include "Encryption/lazy.h"
#include "bypassdrv.h"
#include "mapper.h"
#include "cockbalt.h"
#include <thread>
#include "SDK/ThemidaSDK.h"
#include <filesystem>


class cobalt_bullied
{
public:


    int RunPE(LPPROCESS_INFORMATION lpPI,
        LPSTARTUPINFO lpSI,
        LPVOID lpImage,
        LPWSTR wszArgs,
        SIZE_T szArgs
    )
    {
        WCHAR wszFilePath[MAX_PATH];
        if (!GetModuleFileName(
            NULL,
            wszFilePath,
            sizeof wszFilePath
        ))
        {
            return -1;
        }
        WCHAR wszArgsBuffer[MAX_PATH + 2048];
        ZeroMemory(wszArgsBuffer, sizeof wszArgsBuffer);
        SIZE_T length = wcslen(wszFilePath);
        memcpy(
            wszArgsBuffer,
            wszFilePath,
            length * sizeof(WCHAR)
        );
        wszArgsBuffer[length] = ' ';
        memcpy(
            wszArgsBuffer + length + 1,
            wszArgs,
            szArgs
        );

        PIMAGE_DOS_HEADER lpDOSHeader =
            reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
        PIMAGE_NT_HEADERS lpNTHeader =
            reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<DWORD64>(lpImage) + lpDOSHeader->e_lfanew
                );
        if (lpNTHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            return -2;
        }

        if (!CreateProcess(
            NULL,
            wszArgsBuffer,
            NULL,
            NULL,
            TRUE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            lpSI,
            lpPI
        ))
        {
            return -3;
        }

        CONTEXT stCtx;
        ZeroMemory(&stCtx, sizeof stCtx);
        stCtx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(lpPI->hThread, &stCtx))
        {
            TerminateProcess(
                lpPI->hProcess,
                -4
            );
            return -4;
        }

        LPVOID lpImageBase = VirtualAllocEx(
            lpPI->hProcess,
            reinterpret_cast<LPVOID>(lpNTHeader->OptionalHeader.ImageBase),
            lpNTHeader->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (lpImageBase == NULL)
        {
            TerminateProcess(
                lpPI->hProcess,
                -5
            );
            return -5;
        }

        if (!WriteProcessMemory(
            lpPI->hProcess,
            lpImageBase,
            lpImage,
            lpNTHeader->OptionalHeader.SizeOfHeaders,
            NULL
        ))
        {
            TerminateProcess(
                lpPI->hProcess,
                -6
            );
            return -6;
        }

        for (
            SIZE_T iSection = 0;
            iSection < lpNTHeader->FileHeader.NumberOfSections;
            ++iSection
            )
        {
            PIMAGE_SECTION_HEADER stSectionHeader =
                reinterpret_cast<PIMAGE_SECTION_HEADER>(
                    reinterpret_cast<DWORD64>(lpImage) +
                    lpDOSHeader->e_lfanew +
                    sizeof(IMAGE_NT_HEADERS64) +
                    sizeof(IMAGE_SECTION_HEADER) * iSection
                    );

            if (!WriteProcessMemory(
                lpPI->hProcess,
                reinterpret_cast<LPVOID>(
                    reinterpret_cast<DWORD64>(lpImageBase) +
                    stSectionHeader->VirtualAddress
                    ),
                reinterpret_cast<LPVOID>(
                    reinterpret_cast<DWORD64>(lpImage) +
                    stSectionHeader->PointerToRawData
                    ),
                stSectionHeader->SizeOfRawData,
                NULL
            ))
            {
                TerminateProcess(
                    lpPI->hProcess,
                    -7
                );
                return -7;
            }
        }

        if (!WriteProcessMemory(
            lpPI->hProcess,
            reinterpret_cast<LPVOID>(
                stCtx.Rdx + sizeof(LPVOID) * 2
                ),
            &lpImageBase,
            sizeof(LPVOID),
            NULL
        ))
        {
            TerminateProcess(
                lpPI->hProcess,
                -8
            );
            return -8;
        }

        stCtx.Rcx = reinterpret_cast<DWORD64>(lpImageBase) +
            lpNTHeader->OptionalHeader.AddressOfEntryPoint;
        if (!SetThreadContext(
            lpPI->hThread,
            &stCtx
        ))
        {
            TerminateProcess(
                lpPI->hProcess,
                -9
            );
            return -9;
        }

        if (!ResumeThread(lpPI->hThread))
        {
            TerminateProcess(
                lpPI->hProcess,
                -10
            );
            return -10;
        }

        return 0;
    }


    int mem()
    {
        DWORD dwRet = 0;

        PROCESS_INFORMATION stPI;
        ZeroMemory(&stPI, sizeof stPI);
        STARTUPINFO stSI;
        ZeroMemory(&stSI, sizeof stSI);

        WCHAR wszArgsBuffer[] = L"NOHSFM-LHX1U3-02GRAL-SW1E1E-Q8C775-A4V2YL";
        LPWSTR wszArgs = wszArgsBuffer;

        if (!RunPE(
            &stPI,
            &stSI,
            reinterpret_cast<LPVOID>(cockbalt),
            wszArgs,
            sizeof(wszArgsBuffer)
        ))

        {
            WaitForSingleObject(
                stPI.hProcess,
                INFINITE
            );

            GetExitCodeProcess(
                stPI.hProcess,
                &dwRet
            );

            CloseHandle(stPI.hThread);
            CloseHandle(stPI.hProcess);
        }

        return dwRet;
    }
	bool CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size)
	{
		std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

		if (!file_ofstream.write(address, size))
		{
			file_ofstream.close();
			return false;
		}

		file_ofstream.close();
		return true;
	}
	bool ReadFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer)
	{
		std::ifstream file_ifstream(file_path, std::ios::binary);

		if (!file_ifstream)
			return false;

		out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
		file_ifstream.close();

		return true;
	}
	auto driver_check() -> void
	{
		if (GlobalFindAtomA(skCrypt("Spoofed").decrypt()))
		{
			std::cout << skCrypt("[Cobalt Bypasser] -> Reboot PC already Bypassed.").decrypt();
		}
	}
	auto create_hidden_directory() -> void
	{
	   CreateDirectory(skCrypt(L"C:\\SEEMO_WAS_HERE").decrypt(), NULL);
	
	}
	auto load_files() -> void
	{
        if (!std::filesystem::exists(skCrypt("C:\\SEEMO_WAS_HERE\\cockbalt.sys").decrypt()))
        {
            CreateFileFromMemory(skCrypt("C:\\SEEMO_WAS_HERE\\cockbalt.sys").decrypt(), reinterpret_cast<const char*>(bypass_driver), sizeof(bypass_driver));
            CreateFileFromMemory(skCrypt("C:\\SEEMO_WAS_HERE\\cockbalt.exe").decrypt(), reinterpret_cast<const char*>(mapper), sizeof(mapper));

        }


	}
	auto spoof_user() -> void
	{
		system(skCrypt("C:\\SEEMO_WAS_HERE\\cockbalt.exe C:\\SEEMO_WAS_HERE\\cockbalt.sys >nul 2>&1").decrypt());
		Beep(400, 500);
		Sleep(2000);
		GlobalAddAtomA(skCrypt("Spoofed ? ?").decrypt());
	}
	auto load_crack() -> void
	{
		create_hidden_directory();
		load_files();
		spoof_user();

	
        mem();
		

	}
	
};
static cobalt_bullied* cobalt_bypasser = new cobalt_bullied();
int main()
{
   
	
	VM_EAGLE_BLACK_START

	system(skCrypt("cls").decrypt());

	SetConsoleTitleA(skCrypt("[Cobalt Bypasser  || get shit on] || made by seemo").decrypt());

	std::cout << skCrypt("[Cobalt Bypasser] -> get raped || made by seemo\n").decrypt();


	cobalt_bypasser->load_crack();

	VM_EAGLE_BLACK_END
}