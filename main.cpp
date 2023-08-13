#include <iostream>
#include <string>
#include <fstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <sstream>

using namespace std;

typedef unsigned long DWORD;
typedef unsigned char BYTE;
typedef unsigned short WORD;

HANDLE MapFileToMemory(LPCSTR filename)
{
    streampos size;
    fstream file(filename, ios::in | ios::binary | ios::ate);
    if (file.is_open())
    {
        size = file.tellg();

        char* Memblock = new char[size]();

        file.seekg(0, ios::beg);
        file.read(Memblock, size);
        file.close();

        return Memblock;
    }
    return 0;
}

int RunPortableExecutable(void* Image, const vector<string>& args, char* outputBuffer, size_t outputBufferSize)
{
    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS* NtHeader;
    IMAGE_SECTION_HEADER* SectionHeader;

    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;

    CONTEXT* CTX;

    DWORD64 ImageBase;
    void* pImageBase;

    int count;
    char CurrentFilePath[1024];

    DOSHeader = PIMAGE_DOS_HEADER(Image);
    NtHeader = PIMAGE_NT_HEADERS(DWORD_PTR(Image) + DOSHeader->e_lfanew);

    GetModuleFileNameA(0, CurrentFilePath, 1024);

    if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
    {
        ZeroMemory(&PI, sizeof(PI));
        ZeroMemory(&SI, sizeof(SI));
        SI.cb = sizeof(SI);
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
        HANDLE stdoutRead, stdoutWrite;

        if (!CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0))
        {
            return 1;
        }

        SI.hStdOutput = stdoutWrite;
        SI.hStdError = stdoutWrite;
        SI.dwFlags |= STARTF_USESTDHANDLES;

        stringstream argStringStream;
        for (const auto& arg : args)
        {
            argStringStream << arg << " ";
        }
        string argString = argStringStream.str();

        if (CreateProcessA(CurrentFilePath, const_cast<char*>(argString.c_str()), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
        {
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));
            CTX->ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
            {
                ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Rdx + 0x10), LPVOID(&ImageBase), sizeof(DWORD64), 0);

                pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

                for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
                {
                    SectionHeader = IMAGE_FIRST_SECTION(NtHeader) + count;

                    WriteProcessMemory(PI.hProcess, LPVOID(DWORD_PTR(pImageBase) + SectionHeader->VirtualAddress),
                        LPVOID(DWORD_PTR(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, NULL);
                }

                WriteProcessMemory(PI.hProcess, LPVOID(CTX->Rdx + 0x10), LPVOID(&NtHeader->OptionalHeader.ImageBase), sizeof(DWORD64), NULL);

                CTX->Rcx = DWORD_PTR(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;

                SetThreadContext(PI.hThread, LPCONTEXT(CTX));
                ResumeThread(PI.hThread);

                DWORD bytesRead;
                if (ReadFile(stdoutRead, outputBuffer, outputBufferSize - 1, &bytesRead, NULL))
                {
                    outputBuffer[bytesRead] = '\0';
                }

                CloseHandle(stdoutRead);
                CloseHandle(stdoutWrite);

                return 0;
            }
        }
    }

    return 1;
}
vector<unsigned char> readBytesFromExe(const string& filePath) {
    ifstream file(filePath, ios::in | ios::binary);


    if (!file) {
        cerr << "Error opening file!" << endl;
        return {};
    }

    file.seekg(0, ios::end);
    streampos fileSize = file.tellg();
    file.seekg(0, ios::beg);

    vector<unsigned char> rawData(fileSize);

    file.read(reinterpret_cast<char*>(rawData.data()), fileSize);

    file.close();

    return rawData;
}

int main()
{
        string filepath;
        printf("filepath : ");
        cin >> filepath;
        vector<unsigned char> rawData = readBytesFromExe(filepath);
        void* voidPtr = static_cast<void*>(rawData.data());
        char outputBuffer[1024];

        vector<string> arguments = { "arg1", "you can replace this with your first argument","or even more arguments"}; // Add your desired arguments here

        int result = RunPortableExecutable(voidPtr, arguments, outputBuffer, sizeof(outputBuffer));

        if (result == 0) {
            printf("PE file excecuted succesfully\n"); 
            printf("output: %s",outputBuffer);
        }
        else {
            printf("error : Execution failed\n");
        }
        return 0;
}
