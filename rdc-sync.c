#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        fprintf(stderr, "No arguments\n");
        return 1;
    }
    HANDLE dirHandle = CreateFile(argv[1], FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (dirHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFile failed with 0x%08lX\n", (unsigned long int)GetLastError());
        return 1;
    }
    for (;;) {
        union {
            //FILE_NOTIFY_INFORMATION _notifyInfo;
            BYTE buffer[1024]; // must be DWORD-aligned
        } buffer;
        const DWORD dwNotifyFilter = FILE_NOTIFY_CHANGE_FILE_NAME
                                   | FILE_NOTIFY_CHANGE_DIR_NAME
                                | FILE_NOTIFY_CHANGE_ATTRIBUTES 
                                | FILE_NOTIFY_CHANGE_SIZE 
                                | FILE_NOTIFY_CHANGE_LAST_WRITE 
                                | FILE_NOTIFY_CHANGE_LAST_ACCESS 
                                | FILE_NOTIFY_CHANGE_CREATION 
                                | FILE_NOTIFY_CHANGE_SECURITY;
        DWORD bytesReturned = 0;
        puts("Start watching");
        fflush(stdout);
        BOOL succ = ReadDirectoryChangesW(dirHandle, &buffer, sizeof(buffer), /* bWatchSubtree */ FALSE, dwNotifyFilter, &bytesReturned, NULL, NULL);
        if (!succ) {
            DWORD error = GetLastError();
            const char *msg = "?";
            switch (error) {
            case ERROR_INVALID_PARAMETER: msg = "ERROR_INVALID_PARAMETER"; break;
            case ERROR_NOACCESS: msg = "ERROR_NOACCESS"; break;
            case ERROR_NOTIFY_ENUM_DIR: msg = "ERROR_NOTIFY_ENUM_DIR"; break;
            }
            fprintf(stderr, "ReadDirectoryChangesW failed with 0x%08lX (%s)\n", (unsigned long int)error, msg);
            CloseHandle(dirHandle);
            return 1;
        }
        BYTE *ptr = (BYTE *)&buffer;
        printf("bytes returned = %lu\n", (unsigned long int)bytesReturned);
        while (bytesReturned >= sizeof(FILE_NOTIFY_INFORMATION)) {
            FILE_NOTIFY_INFORMATION *notifyInfo = (FILE_NOTIFY_INFORMATION *)ptr;
            const char *action = "???";
            switch (notifyInfo->Action) {
            case FILE_ACTION_ADDED: action = "FILE_ACTION_ADDED"; break;
            case FILE_ACTION_REMOVED: action = "FILE_ACTION_REMOVED"; break;
            case FILE_ACTION_MODIFIED: action = "FILE_ACTION_MODIFIED"; break;
            case FILE_ACTION_RENAMED_OLD_NAME: action = "FILE_ACTION_RENAMED_OLD_NAME"; break;
            case FILE_ACTION_RENAMED_NEW_NAME: action = "FILE_ACTION_RENAMED_NEW_NAME"; break;
            }
            printf("%s %.*ls\n", action, (int)(notifyInfo->FileNameLength / sizeof(WCHAR)), notifyInfo->FileName);
            if (notifyInfo->NextEntryOffset == 0 || bytesReturned <= notifyInfo->NextEntryOffset) {
                break;
            }
            bytesReturned -= notifyInfo->NextEntryOffset;
            ptr += notifyInfo->NextEntryOffset;
        }
    }
    CloseHandle(dirHandle);
}
