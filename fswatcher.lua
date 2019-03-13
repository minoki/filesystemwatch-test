local ffi = require "ffi"
local bitlib = assert(bit32 or bit, "Neither bit32 (Lua 5.2) nor bit (LuaJIT) found") -- Lua 5.2 or LuaJIT
ffi.cdef[[
    typedef int BOOL;
    typedef unsigned int UINT;
    typedef uint32_t DWORD;
    typedef void *HANDLE;
    typedef uintptr_t ULONG_PTR;
    typedef uint16_t WCHAR;
    typedef struct _OVERLAPPED {
        ULONG_PTR Internal;
        ULONG_PTR InternalHigh;
        union {
            struct {
                DWORD Offset;
                DWORD OffsetHigh;
            };
            void *Pointer;
        };
        HANDLE hEvent;
    } OVERLAPPED;
    typedef struct _FILE_NOTIFY_INFORMATION {
        DWORD NextEntryOffset;
        DWORD Action;
        DWORD FileNameLength;
        WCHAR FileName[?];
    } FILE_NOTIFY_INFORMATION;
    typedef void (__stdcall *LPOVERLAPPED_COMPLETION_ROUTINE)(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, OVERLAPPED *lpOverlapped);
    DWORD GetLastError();
    BOOL CloseHandle(HANDLE hObject);
    HANDLE CreateFileA(const char *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, void *lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    HANDLE CreateIoCompletionPort(HANDLE fileHandle, HANDLE existingCompletionPort, ULONG_PTR completionKey, DWORD numberOfConcurrentThreads);
    BOOL ReadDirectoryChangesW(HANDLE hDirectory, void *lpBuffer, DWORD nBufferLength, BOOL bWatchSubtree, DWORD dwNotifyFilter, DWORD *lpBytesReturned, OVERLAPPED *lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpOverlappedCompletionRoutine);
    BOOL GetQueuedCompletionStatus(HANDLE CompletionPort, DWORD *lpNumberOfBytes, ULONG_PTR *lpCompletionKey, OVERLAPPED **lpOverlapped, DWORD dwMilliseconds);
    int MultiByteToWideChar(UINT CodePage, DWORD dwFlags, const char *lpMultiByteStr, int cbMultiByte, WCHAR *lpWideCharStr, int cchWideChar);
    int WideCharToMultiByte(UINT CodePage, DWORD dwFlags, const WCHAR *lpWideCharStr, int cchWideChar, char *lpMultiByteStr, int cbMultiByte, const char *lpDefaultChar, BOOL *lpUsedDefaultChar);
    DWORD GetFullPathNameA(const char *lpFileName, DWORD nBufferLength, char *lpBuffer, char **lpFilePart);
    uint64_t GetTickCount64();
]]
local ERROR_FILE_NOT_FOUND    = 0x0002
local ERROR_PATH_NOT_FOUND    = 0x0003
local ERROR_ACCESS_DENIED     = 0x0005
local ERROR_INVALID_PARAMETER = 0x0057
local WAIT_TIMEOUT            = 0x0102
local ERROR_NOACCESS          = 0x03E6
local ERROR_ABANDONED_WAIT_0  = 0x02DF
local ERROR_NOTIFY_ENUM_DIR   = 0x03FE
local FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
local FILE_FLAG_OVERLAPPED       = 0x40000000
local OPEN_EXISTING = 3
local FILE_SHARE_READ   = 0x00000001
local FILE_SHARE_WRITE  = 0x00000002
local FILE_SHARE_DELETE = 0x00000004
local INVALID_HANDLE_VALUE = ffi.cast("void *", -1)
local FILE_LIST_DIRECTORY  = 0x1
local FILE_NOTIFY_CHANGE_FILE_NAME   = 0x00000001
local FILE_NOTIFY_CHANGE_DIR_NAME    = 0x00000002
local FILE_NOTIFY_CHANGE_ATTRIBUTES  = 0x00000004
local FILE_NOTIFY_CHANGE_SIZE        = 0x00000008
local FILE_NOTIFY_CHANGE_LAST_WRITE  = 0x00000010
local FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
local FILE_NOTIFY_CHANGE_CREATION    = 0x00000040
local FILE_NOTIFY_CHANGE_SECURITY    = 0x00000100
local FILE_ACTION_ADDED            = 0x00000001
local FILE_ACTION_REMOVED          = 0x00000002
local FILE_ACTION_MODIFIED         = 0x00000003
local FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
local FILE_ACTION_RENAMED_NEW_NAME = 0x00000005
local CP_ACP = 0
local CP_UTF8 = 65001
local C = ffi.C
local function format_error(name, lasterror)
    return string.format("%s failed with %d (0x%04x)", name, lasterror, lasterror)
end
local function wcs_to_mbs(wstr, wstrlen, codepage)
    if wstrlen == 0 then
        return ""
    end
    -- wstr: FFI uint16_t[?]
    -- wstrlen: length of wstr, or -1 if NUL-terminated
    codepage = codepage or CP_ACP
    local dwFlags = 0
    local result = C.WideCharToMultiByte(codepage, dwFlags, wstr, wstrlen, nil, 0, nil, nil)
    if result <= 0 then
        -- Failed
        local lasterror = C.GetLastError()
        -- ERROR_INSUFFICIENT_BUFFER
        -- ERROR_INVALID_FLAGS
        -- ERROR_INVALID_PARAMETER
        -- ERROR_NO_UNICODE_TRANSLATION
        return nil, format_error("WideCharToMultiByte", lasterror)
    end
    local mbsbuf = ffi.new("char[?]", result)
    result = C.WideCharToMultiByte(codepage, dwFlags, wstr, wstrlen, mbsbuf, result, nil, nil)
    if result <= 0 then
        -- Failed
        local lasterror = C.GetLastError()
        -- ERROR_INSUFFICIENT_BUFFER
        -- ERROR_INVALID_FLAGS
        -- ERROR_INVALID_PARAMETER
        -- ERROR_NO_UNICODE_TRANSLATION
        return nil, format_error("WideCharToMultiByte", lasterror)
    end
    return ffi.string(mbsbuf, result)
end
local function mbs_to_wcs(str, codepage)
    if str == "" then
        return ffi.new("WCHAR[0]")
    end
    codepage = codepage or CP_ACP
    local dwFlags = 0
    local result = C.MultiByteToWideChar(codepage, dwFlags, str, #str, nil, 0)
    if result <= 0 then
        local lasterror = C.GetLastError()
        return nil, format_error("MultiByteToWideChar", lasterror)
    end
    local wcsbuf = ffi.new("WCHAR[?]", result)
    result = C.MultiByteToWideChar(codepage, dwFlags, str, #str, wcsbuf, result)
    if result <= 0 then
        local lasterror = C.GetLastError()
        return nil, format_error("MultiByteToWideChar", lasterror)
    end
    return wcsbuf
end
local ws = {0x3042}
local resultstr = wcs_to_mbs(ffi.new("WCHAR[1]", ws), 1, CP_UTF8)
print(#resultstr)
print(string.format("%02x %02x %02x", string.byte(resultstr, 1, -1)))
print(resultstr == "\xE3\x81\x82") -- \u{XXXX} notation is not available on LuaJIT
assert(bitlib.bor(FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE) == FILE_SHARE_READ + FILE_SHARE_WRITE + FILE_SHARE_DELETE)
local function get_full_path_name(filename)
    local bufsize = 1024
    local buffer
    local filePartPtr = ffi.new("char*[1]")
    local result
    repeat
        buffer = ffi.new("char[?]", bufsize)
        result = C.GetFullPathNameA(filename, bufsize, buffer, filePartPtr)
        if result == 0 then
            local lasterror = C.GetLastError()
            return nil, format_error("GetFullPathNameA", lasterror)
        elseif bufsize < result then
            -- result: buffer size required to hold the path + terminating NUL
            bufsize = result
        end
    until result < bufsize
    local fullpath = ffi.string(buffer, result)
    local filePart = ffi.string(filePartPtr[0])
    local dirPart = ffi.string(buffer, filePartPtr[0] - buffer)
    return fullpath, filePart, dirPart
end
print(get_full_path_name("../fswatcher/fswatcher.lua"))
print(get_full_path_name(".."))
local dirhandle_meta = {}
dirhandle_meta.__index = dirhandle_meta
function dirhandle_meta:close()
    if self._rawhandle ~= nil then
        C.CloseHandle(ffi.gc(self._rawhandle, nil))
        self._rawhandle = nil
    end
end
local function open_directory(dirname)
    local dwShareMode = bitlib.bor(FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE)
    local dwFlagsAndAttributes = bitlib.bor(FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED)
    local handle = C.CreateFileA(dirname, FILE_LIST_DIRECTORY, dwShareMode, nil, OPEN_EXISTING, dwFlagsAndAttributes, nil)
    if handle == INVALID_HANDLE_VALUE then
        local lasterror = C.GetLastError()
        print("Failed to open "..dirname)
        return nil, format_error("CreateFileA", lasterror)
    end
    local overlappedPtr = ffi.new("OVERLAPPED[1]")
    return setmetatable({
        name = dirname,
        _rawhandle = ffi.gc(handle, C.CloseHandle),
        _overlappedPtr = overlappedPtr,
    }, dirhandle_meta)
end
function dirhandle_meta:start_watch(watchSubtree)
    local dwNotifyFilter = bitlib.bor(FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_SIZE, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_LAST_ACCESS, FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_SECURITY)
    local buffer = self._buffer
    if not buffer then
        buffer = ffi.new("char[?]", 1024)
        self._buffer = buffer
    end
    local bufferSize = ffi.sizeof(buffer)
    local result = C.ReadDirectoryChangesW(self._rawhandle, self._buffer, bufferSize, watchSubtree, dwNotifyFilter, nil, self._overlappedPtr, nil)
    if result == 0 then
        local lasterror = C.GetLastError()
        return nil, format_error("ReadDirectoryChangesW", lasterror)
    end
    return true
end
local ActionTable = {
    [FILE_ACTION_ADDED] = "added",
    [FILE_ACTION_REMOVED] = "removed",
    [FILE_ACTION_MODIFIED] = "modified",
    [FILE_ACTION_RENAMED_OLD_NAME] = "rename_from",
    [FILE_ACTION_RENAMED_NEW_NAME] = "rename_to",
}
function dirhandle_meta:process(numberOfBytes)
    local buffer = self._buffer
    numbefOfBytes = math.min(numberOfBytes, ffi.sizeof(buffer))
    local ptr = ffi.cast("char *", buffer)
    local structSize = ffi.sizeof("FILE_NOTIFY_INFORMATION", 1)
    local t = {}
    while numberOfBytes >= structSize do
        local notifyInfo = ffi.cast("FILE_NOTIFY_INFORMATION*", ptr)
        local nextEntryOffset = notifyInfo.NextEntryOffset
        local action = notifyInfo.Action
        local fileNameLength = notifyInfo.FileNameLength
        local fileName = notifyInfo.FileName
        local u = { action = ActionTable[action], filename = wcs_to_mbs(fileName, fileNameLength / 2) }
        table.insert(t, u)
        if nextEntryOffset == 0 or numberOfBytes <= nextEntryOffset then
            break
        end
        numberOfBytes = numberOfBytes - nextEntryOffset
        ptr = ptr + nextEntryOffset
    end
    return t
end

local fswatcher_meta = {}
fswatcher_meta.__index = fswatcher_meta
local function new_watcher()
    local port = C.CreateIoCompletionPort(INVALID_HANDLE_VALUE, nil, 0, 0)
    if port == nil then
        local lasterror = C.GetLastError()
        return nil, format_error("CreateIoCompletionPort", lasterror)
    end
    return setmetatable({
        _rawport = port,
        _pending = {},
        -- directoryies[dirname] = {set of <watched file name, wanted events>}
        _directories = {},
    }, fswatcher_meta)
end
local function add_directory(self, dirname)
    local t = self._directories[dirname]
    if not t then
        local dir, err = open_directory(dirname)
        if not dir then
            return dir, err
        end
        t = { dir = dir, dirname = dirname, files = {} }
        table.insert(self, t)
        local i = #self
        local result = C.CreateIoCompletionPort(dir._rawhandle, self._rawport, i, 0)
        if result == nil then
            local lasterror = C.GetLastError()
            return nil, format_error("CreateIoCompletionPort", lasterror)
        end
        self._directories[dirname] = t
        local result, err = dir:start_watch(false)
        if not result then
            return result, err
        end
    end
    return t
end
function fswatcher_meta:add_file(path, ...)
    local fullpath, filename, dirname = get_full_path_name(path)
    local t, err = add_directory(self, dirname)
    if not t then
        return t, err
    end
    t.files[filename] = path
    return true
end
local INFINITE = 0xFFFFFFFF
local function get_queued(self, timeout)
    local startTime = C.GetTickCount64()
    local timeout_ms
    if timeout == nil then
        timeout_ms = INFINITE
    else
        timeout_ms = timeout * 1000
    end
    local numberOfBytesPtr = ffi.new("DWORD[1]")
    local completionKeyPtr = ffi.new("ULONG_PTR[1]")
    local lpOverlapped = ffi.new("OVERLAPPED*[1]")
    repeat
        local result = C.GetQueuedCompletionStatus(self._rawport, numberOfBytesPtr, completionKeyPtr, lpOverlapped, timeout_ms)
        if result == 0 then
            local lasterror = C.GetLastError()
            if lasterror == WAIT_TIMEOUT then
                return nil, "timeout"
            else
                return nil, format_error("GetQueuedCompletionStatus", lasterror)
            end
        end
        local numberOfBytes = numberOfBytesPtr[0]
        local completionKey = tonumber(completionKeyPtr[0])
        local dir_t = assert(self[completionKey], "invalid completion key: " .. tostring(completionKey))
        local t = dir_t.dir:process(numberOfBytes)
        dir_t.dir:start_watch(false)
        local found = false
        for i,v in ipairs(t) do
            local path = dir_t.files[v.filename]
            if path then
                found = true
                table.insert(self._pending, {path = path, action = v.action})
            end
        end
        if found then
            return true
        end
        if timeout_ms ~= INFINITE then
            local tt = C.GetTickCount64()
            timeout_ms = timeout_ms - (tt - startTime)
            startTime = tt
        end
    until timeout_ms < 0
    return nil, "timeout"
end
function fswatcher_meta:next(timeout)
    if #self._pending > 0 then
        local result = table.remove(self._pending, 1)
        get_queued(self, 0)
        return result
    else
        local result, err = get_queued(self, timeout)
        if result == nil then
            return nil, err
        end
        return table.remove(self._pending, 1)
    end
end
function fswatcher_meta:close()
    if self._rawport ~= nil then
        for i,v in ipairs(self) do
            v.dir:close()
        end
        C.CloseHandle(ffi.gc(self._rawport, nil))
        self._rawport = nil
    end
end
--[==[

local watcher = fswatcher.new() -- fswatcher.new_utf8()
watcher:add_dir("path/to/dir", --[[ recursive ]] true, "filename", "dirname", "attributes") --[[oneshot]]
watcher:add_file("path/to/file", "changefilename", "attributes", "size") --[[oneshot]]
result, err = watcher:next([timeout])
if result then
    result.path, result.change == "add", "remove", "modify", "move_from", "move_to"
else
    -- result == nil
    -- err == "timeout" if timed out
end
for result in watcher:iter([timeout]) do
end
watcher:close()

]==]
local watcher = new_watcher()
assert(watcher:add_file("rdc-sync.c"))
assert(watcher:add_file("sub2/hoge"))
for i = 1, 10 do
    local result, err = watcher:next(2)
    if err == "timeout" then
        print(os.date(), "timeout")
    else
        assert(result, err)
        print(os.date(), result.path, result.action)
    end
end
watcher:close()
