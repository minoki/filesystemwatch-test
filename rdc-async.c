#include <windows.h>
#include <stdio.h>
#include <assert.h>

struct DirWatcher {
    HANDLE directoryHandle;
    union {
        DWORD _dummy;
        BYTE buffer[1024]; // DWORD-aligned
    } buffer;
};

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        fprintf(stderr, "No arguments\n");
        return 1;
    }
    HANDLE completionPort = NULL;
    struct DirWatcher *watchers = calloc(argc, sizeof(struct DirWatcher));
    for (int i = 1; i < argc; ++i) {
        HANDLE dirHandle = CreateFile(argv[i], FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
        if (dirHandle == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "CreateFile(%s) failed with 0x%08lX\n", argv[i], (unsigned long int)GetLastError());
            return 1;
        }
        completionPort = CreateIoCompletionPort(dirHandle, completionPort, i-1, 0);
        if (completionPort == NULL) {
            fprintf(stderr, "CreateIoCompletionPort failed with 0x%08lX\n", (unsigned long int)GetLastError());
            return 1;
        }
        printf("Opened %s\n", argv[i]);
        watchers[i-1].directoryHandle = dirHandle;
    }
    OVERLAPPED overlapped = {};
    for (int i = 0; i < argc - 1; ++i) {
        const DWORD dwNotifyFilter = FILE_NOTIFY_CHANGE_FILE_NAME
                                   | FILE_NOTIFY_CHANGE_DIR_NAME
                                   | FILE_NOTIFY_CHANGE_ATTRIBUTES 
                                   | FILE_NOTIFY_CHANGE_SIZE 
                                   | FILE_NOTIFY_CHANGE_LAST_WRITE 
                                   | FILE_NOTIFY_CHANGE_LAST_ACCESS 
                                   | FILE_NOTIFY_CHANGE_CREATION 
                                   | FILE_NOTIFY_CHANGE_SECURITY;
        BOOL succ = ReadDirectoryChangesW(watchers[i].directoryHandle, &watchers[i].buffer, sizeof(watchers[i].buffer), /* bWatchSubtree */ FALSE, dwNotifyFilter, NULL, &overlapped, NULL);
        if (!succ) {
            DWORD error = GetLastError();
            const char *msg = "?";
            switch (error) {
            case ERROR_INVALID_PARAMETER: msg = "ERROR_INVALID_PARAMETER"; break;
            case ERROR_NOACCESS: msg = "ERROR_NOACCESS"; break;
            case ERROR_NOTIFY_ENUM_DIR: msg = "ERROR_NOTIFY_ENUM_DIR"; break;
            }
            fprintf(stderr, "ReadDirectoryChangesW failed with 0x%08lX (%s)\n", (unsigned long int)error, msg);
            return 1;
        }
    }
    for (int k = 0; k < 20; ++k) {
        DWORD bytesReturned = 0;
        ULONG_PTR completionKey = 0;
        OVERLAPPED *overlappedPtr = NULL;
        puts("Start watching...");
        fflush(stdout);
        BOOL result = GetQueuedCompletionStatus(completionPort, &bytesReturned, &completionKey, &overlappedPtr, INFINITE);
        if (!result) {
            DWORD error = GetLastError();
            if (error == WAIT_TIMEOUT) {
                puts("Timeout");
                continue;
            }
            const char *msg = "?";
            switch (error) {
            case ERROR_INVALID_PARAMETER: msg = "ERROR_INVALID_PARAMETER"; break;
            case ERROR_ABANDONED_WAIT_0: msg = "ERROR_ABANDONED_WAIT_0"; break;
            }
            fprintf(stderr, "GetQueuedCompletionStatus failed with 0x%08lX (%s)\n", (unsigned long int)error, msg);
            return 1;
        }
        assert(completionKey < argc - 1);
        int i = completionKey;
        BYTE *ptr = (BYTE *)&watchers[i].buffer;
        printf("[%d] bytes returned = %lu\n", i, (unsigned long int)bytesReturned);
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
        const DWORD dwNotifyFilter = FILE_NOTIFY_CHANGE_FILE_NAME
                                   | FILE_NOTIFY_CHANGE_DIR_NAME
                                   | FILE_NOTIFY_CHANGE_ATTRIBUTES 
                                   | FILE_NOTIFY_CHANGE_SIZE 
                                   | FILE_NOTIFY_CHANGE_LAST_WRITE 
                                   | FILE_NOTIFY_CHANGE_LAST_ACCESS 
                                   | FILE_NOTIFY_CHANGE_CREATION 
                                   | FILE_NOTIFY_CHANGE_SECURITY;
        BOOL succ = ReadDirectoryChangesW(watchers[i].directoryHandle, &watchers[i].buffer, sizeof(watchers[i].buffer), /* bWatchSubtree */ FALSE, dwNotifyFilter, NULL, &overlapped, NULL);
        if (!succ) {
            DWORD error = GetLastError();
            const char *msg = "?";
            switch (error) {
            case ERROR_INVALID_PARAMETER: msg = "ERROR_INVALID_PARAMETER"; break;
            case ERROR_NOACCESS: msg = "ERROR_NOACCESS"; break;
            case ERROR_NOTIFY_ENUM_DIR: msg = "ERROR_NOTIFY_ENUM_DIR"; break;
            }
            fprintf(stderr, "ReadDirectoryChangesW failed with 0x%08lX (%s)\n", (unsigned long int)error, msg);
            return 1;
        }
    }
}
