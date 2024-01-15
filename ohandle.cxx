// Prints open handles
// By default, only shows disk file handles. Use -a to show all handles.
// Due to the security settings of some processes, not all data is shown.
// Due to Windows design issues when querying named pipes, not all of those are shown.
// Due to inherent race conditions between getting all handles and enumerating them, some are not shown.
// Due to some handle types not supporting duplication, some are not shown.
// Most of these issues have been solved by creating and installing device drivers. There are
//   many examples of this available on the internet. That's overkill for what I needed from this tool.
// The performance cost of using new threads per call instead of a device driver is that overall runtime
// is about 1.5x slower than handle.exe for file matching. But this is also 2x faster than handle.exe for -s.

#include <vector>
#include <map>
#include <memory>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

using namespace std;

#pragma comment( lib, "ntdll.lib" )
#pragma comment( lib, "advapi32.lib" )

static bool verbose = false;

#define INVALID_PID_VALUE ( (ULONGLONG) INVALID_HANDLE_VALUE )
#define SystemExtendedHandleInformation ( (SYSTEM_INFORMATION_CLASS) 64 )
#define err_STATUS_INFO_LENGTH_MISMATCH 0xc0000004

typedef struct _SYSTEM_HANDLE
{
    PVOID object;
    ULONG_PTR pid;
    HANDLE handleValue;
    ULONG grantedAccess;
    USHORT creatorBackTraceIndex;
    USHORT objectTypeIndex;
    ULONG handleAttributes;
    ULONG reserved;

    void Trace()
    {
        printf( "  pid %llu handle %llu type %u attrib %u object %p grantedAccess %#x unk %u\n",
                pid, (ULONGLONG) handleValue, objectTypeIndex, handleAttributes, object, grantedAccess, reserved );
    }
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR numberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

class XHandle
{
    private:
        HANDLE _h;
    public:
        XHandle( HANDLE h = INVALID_HANDLE_VALUE ) : _h( h ) {};
        ~XHandle() { if ( ( INVALID_HANDLE_VALUE != _h ) && ( 0 != _h ) ) CloseHandle( _h ); }
};

const UCHAR handleTypeDirectory = 3;
const UCHAR handleTypeProcess = 7;
const UCHAR handleTypeFile = 40;

const char * HandleTypes[256]
{
    0, 0, "Type", "Directory", "SymbolicLink", "Token", "Job", "Process",                        //  0-7
    "Thread", "Partition", "UserApcReserve", "IoCompletionReserve",                              //  8-11
    "ActivityReference", "ProcessStateChange", "ThreadStateChange", "CpuPartition",              // 12-15
    "PsSiloContextPaged", "PsSiloContextNonPaged", "DebugObject", "Event",                       // 16-19
    "Mutant", "Callback", "Semaphore", "Timer",                                                  // 20-23
    "IrTimer", "Profile", "KeyedEvent", "WindowStation",                                         // 24-27
    "Desktop", "Composition", "RawInputManager", "CoreMessaging",                                // 28-31
    "ActivationObject", "TpWorkerFactory", "Adapter", "Controller",                              // 32-35
    "Device", "Driver", "IoCompletion", "WaitCompletionPacket",                                  // 36-39
    "File", "IoRing", "TmTm", "TmTx", "TmRm", "TmEn", "Section", "Session",                      // 40-47
    "Key", "RegistryTransaction", "DmaAdapter", "AlpcPort",                                      // 48-51
    "EnergyTracker", "PowerRequest", "WmiGuid", "EtwRegistration",                               // 52-55
    "EtwSessionDemuxEntry", "EtwConsumer", "CoverageSampler", "PcwObject",                       // 56-59
    "FilterConnectionPort", "FilterCommunicationPort", "NdisCmState", "DgxgkSharedResource",     // 60-63

    "DxgkSharedKeyedMutexObject", "DgxkSharedSyncObject", "DxgkSharedSwapChainObject", "DxgkDisplayManagerObject",     // 64-67
    "DxgkSharedProtectedSessionObject", "DxgkSharedBundleObject", "DgxkCompositionObject", "VRegConfigurationContext", // 68-71
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,

    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,                            // 128
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,

    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,                            // 192
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,                        0, 0, 0, 0, 0, 0, 0, 0,
};

void usage()
{
    printf( "usage:         ohandle [-p:PID] [-v] [pattern]\n" );
    printf( "  arguments:   -a           All handles, not just disk files\n" );
    printf( "               -p:PID       Limit results to this PID or binary name prefix\n" );
    printf( "               -s           Summary handle counts for all or just -p\n" );
    printf( "               -v           verbose; show errors and progress\n" );
    printf( "               pattern      case-insensitive disk file filter if not -a or -s\n" );
    printf( "  e.g.:        ohandle -p:6492\n" );
    printf( "               ohandle adobe\n" );
    printf( "               ohandle -p:6482 v:\n" );
    printf( "               ohandle\n" );
    printf( "               ohandle -s\n" );
    printf( "               ohandle -s -p:outlook\n" );

    exit( 1 );
} //usage

const char * FileTypeString( DWORD x )
{
    if ( FILE_TYPE_CHAR == x )
        return "lpt/con";
    if ( FILE_TYPE_DISK == x )
        return "disk";
    if ( FILE_TYPE_PIPE == x )
        return "pipe";
    if ( FILE_TYPE_REMOTE == x )
        return "remote";
    return "unknown";
} //FileTypeString

struct GFTPState
{
    HANDLE h;
    DWORD result;
};

DWORD WINAPI GetFileTypeProc( LPVOID param )
{
    GFTPState * pstate = (GFTPState *) param;
    pstate->result = GetFileType( pstate->h );
    return 0;
} //GetFileTypeProc

#pragma warning( disable: 6258) // use of TerminateThread

DWORD RobustGetFileType( HANDLE h )
{
    // GetFileType hangs for pipes. Use a separate thread and kill it if it appears to be hung.

    GFTPState state;
    state.h = h;
    state.result = 0;
    HANDLE hThread = CreateThread( 0, 0, GetFileTypeProc, &state, 0, 0 );
    if ( hThread )
    {
        XHandle xThread( hThread );
        DWORD wait = WaitForSingleObject( hThread, 50 );
        if ( WAIT_TIMEOUT == wait )
        {
            // Terminating threads generally leaves a process in a broken state. It's really bad to continue
            // execution after termination because there may be leaks, locks held and never released, etc.
            // But if this thread is truly blocked on a named pipe it's generally safe to terminate it and
            // continue without too much damage. By waiting 50ms, it's very likely that the thread is safe
            // to terminate.

            if ( verbose )
                printf( "  terminating thread... " );
            TerminateThread( hThread, 0 );
            if ( verbose )
                printf( "terminated\n" );
            WaitForSingleObject( hThread, INFINITE ); // Terminating a thread sets the handle to a signaled state
        }
    }

    return state.result;
} //RobusGetFileType

bool SetPrivilege( HANDLE hToken, LPCTSTR lpszPrivilege, bool bEnablePrivilege ) 
{
    LUID luid;
    if ( !LookupPrivilegeValue( NULL, lpszPrivilege, &luid ) )
    {
        printf( "LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return false; 
    }

    TOKEN_PRIVILEGES tp;
    memset( &tp, 0, sizeof( tp ) );
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof( TOKEN_PRIVILEGES ), 0, 0 ) )
    { 
        printf( "AdjustTokenPrivileges error: %u\n", GetLastError() ); 
        return false; 
    } 

    if ( ERROR_NOT_ALL_ASSIGNED == GetLastError() )
    {
        printf( "The token does not have the specified privilege.\n");
        return false;
    } 

    return true;
} //SetPrivilege

bool SetDebugPrivilege()
{
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hToken;
    if ( OpenProcessToken( hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken ) )
    {
        bool worked = SetPrivilege( hToken, SE_DEBUG_NAME, true );
        CloseHandle( hToken );
        return worked;
    }

    return false;
} //SetDebugPrivilege

bool FindProcessPath( HANDLE hProc, vector<char> & buf )
{
    char * pathName = buf.data();
    pathName[0] = 0; // in case of failure, return an empty string
    DWORD len = (DWORD) buf.size();
    return QueryFullProcessImageNameA( hProc, 0, pathName, &len );
} //FindProcessPath

bool FindFilePath( HANDLE hFile, vector<char> & buf )
{
    char * pathName = buf.data();
    pathName[0] = 0; // in case of failure, return an empty string
    return GetFinalPathNameByHandleA( hFile, pathName, (DWORD) buf.size(), FILE_NAME_OPENED ); //NORMALIZED );
} //FindFileName

int begins_with( const char * str, const char * start )
{
    while ( *str && *start )
    {
        if ( tolower( *str ) != tolower( *start ) )
            return false;

        str++;
        start++;
    }

    if ( *start )
        return false; // str is shorter than start

    return true;
} //begins_with

ULONGLONG FindProcess( const char * pname )
{
    // look for the first process starting with the name and return its PID

    vector<DWORD> aProcs( 64 );
    DWORD cbNeeded = 0;
    do
    {
        BOOL ok = EnumProcesses( aProcs.data(), (DWORD) aProcs.size() * sizeof( DWORD ), & cbNeeded );
        if ( !ok )
        {
            printf( "can't enumerate processes, error %d\n", GetLastError() );
            usage();
        }

        if ( ( aProcs.size() * sizeof( DWORD ) ) == cbNeeded )
        {
            aProcs.resize( aProcs.size() * 2 );
            if ( verbose )
                printf( "EnumProcess buffer resized to %zu\n", aProcs.size() );
        }
        else
            break;
    } while( true );

    vector<char> bufferImageName( 4096 );
    DWORD cProcesses = cbNeeded / sizeof( DWORD );
    for ( DWORD i = 0; i < cProcesses; i++ )
    {
        HANDLE hProc = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, aProcs[ i ] );
        if ( 0 != hProc )
        {
            if ( FindProcessPath( hProc, bufferImageName ) )
            {
                char * imageName = (char *) bufferImageName.data();
                char * plast = strrchr( imageName, '\\' );
                if ( plast )
                {
                    if ( begins_with( plast + 1, pname ) )
                    {
                        printf( "looking at PID %u - %s\n", aProcs[ i ], imageName );
                        return aProcs[ i ];
                    }
                }
            }
        }
    }

    return INVALID_PID_VALUE;
} //FindProcess

// return true if pattern is found in str case-insensitive. assume pat is all lowercase already.
bool fstristr( const char * str, const char * pat )
{
    while ( *str )
    {
        const char * s = str;
        const char * p = pat;

        while ( *s && *p && ( tolower( *s ) == *p ) )
        {
            p++;
            s++;
        }

        if ( !*p )
            return true;

        str++;
    }

    return false;
} //fstristr

#pragma warning( disable: 4996) // use of _strlwr

int main( int argc, char *argv[] )
{
    SetDebugPrivilege(); // needed to see into some svchost.exe instances and other processes. ignore if this fails

    const char * pattern = 0;
    ULONGLONG targetPid = INVALID_PID_VALUE;
    bool allHandles = false;
    bool summary = false;
    char * pidLookup = 0;

    for ( int i = 1; i < argc; i++ )
    {
        if ( ( '-' == argv[i][0] ) || ( '/' == argv[i][0] ) )
        {
            char arg = argv[i][1];

            if ( 'a' == arg )
                allHandles = true;
            else if ( 'p' == arg && ':' == argv[i][2] )
            {
                targetPid = strtoull( argv[i] + 3, 0, 0 );
                if ( 0 == targetPid )
                    pidLookup = argv[i] + 3;
            }
            else if ( 's' == arg )
                summary = true;
            else if ( 'v' == arg )
                verbose = true;
            else
                usage();
        }
        else if ( pattern )
            usage();
        else
            pattern = _strlwr( argv[i] );
    }

    if ( pidLookup )
    {
        targetPid = FindProcess( pidLookup );
        if ( INVALID_PID_VALUE == targetPid )
        {
            printf( "can't find or don't have access to process specified with -p\n" );
            usage();
        }
    }

    size_t handleInfoSize = 0x10000000;
    unique_ptr<byte> handleInfoBuffer( new byte[ handleInfoSize ] );

    do
    {
        NTSTATUS rv = NtQuerySystemInformation( SystemExtendedHandleInformation, handleInfoBuffer.get(), (ULONG) handleInfoSize, 0 );
        if ( err_STATUS_INFO_LENGTH_MISMATCH == rv )
        {
            handleInfoSize *= 2;
            handleInfoBuffer.reset( new byte[ handleInfoSize ] );
            if ( verbose )
                printf( "grew array to %zu bytes given error %#x\n", handleInfoSize, rv );
        }
        else if ( NT_SUCCESS( rv ) )
            break;
        else
        {
            printf( "NtQuerySystemInformation failed with error %#x\n", rv );
            exit( 1 );
        }
    } while( true );

    SYSTEM_HANDLE_INFORMATION_EX * phandleInfo = (SYSTEM_HANDLE_INFORMATION_EX *) handleInfoBuffer.get();
    printf( "searching through %llu handles...\n", phandleInfo->numberOfHandles );

    SYSTEM_HANDLE * hArray = & ( phandleInfo->Handles[0] );
    vector<byte> bufferObjInfo( 4096 );
    vector<char> bufferImageName( 4096 );
    vector<char> bufferPath( 4096 );
    map<ULONG_PTR,HANDLE> pidToHandle;
    map<ULONG_PTR,char *> pidToImage;
    ULONGLONG prevPid = INVALID_PID_VALUE;
    vector<size_t> handleCounts( 256 );

    for ( size_t i = 0; i < phandleInfo->numberOfHandles; i++ )
    {
        SYSTEM_HANDLE & sh = hArray[ i ];
        if ( ( INVALID_PID_VALUE == targetPid ) || ( sh.pid == targetPid ) )
        {
            if ( summary )
            {
                handleCounts[ sh.objectTypeIndex ]++;
                continue;
            }

            if ( allHandles || ( handleTypeFile == sh.objectTypeIndex ) )
            {
                if ( !allHandles && handleTypeFile != sh.objectTypeIndex )
                {
                    if ( verbose )
                        printf( "  skipping object type %u\n", sh.objectTypeIndex );
                    continue;
                }

                HANDLE hProc;
                map<ULONG_PTR,HANDLE>::iterator iter = pidToHandle.find( sh.pid );
                if ( iter == pidToHandle.end() )
                {
                    if ( 0 == sh.pid )
                        hProc = 0;
                    else
                    {
                        hProc = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, (DWORD) sh.pid );
                        if ( 0 == hProc && verbose )
                            printf( "unable to get hProc for pid %llu\n", sh.pid );
                    }

                    pidToHandle[ sh.pid ] = hProc; // regardless of whether it worked, cache the result
                }
                else
                    hProc = iter->second;
    
                if ( 0 == hProc )
                    continue;
    
                HANDLE hDup = INVALID_HANDLE_VALUE;
                if ( ( handleTypeFile == sh.objectTypeIndex ) ||
                     ( allHandles && ( handleTypeProcess == sh.objectTypeIndex ) ) )
                {
                    if ( !DuplicateHandle( hProc, (HANDLE) sh.handleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS) )
                    {
                        if ( verbose )
                            printf( "duplicating handle type %s failed for pid %llu error %d\n", HandleTypes[ sh.objectTypeIndex ], sh.pid, GetLastError() );
                        continue;
                    }
                }
    
                XHandle xDup( hDup );
                DWORD fileType = 0;
                if ( handleTypeFile == sh.objectTypeIndex )
                    fileType = RobustGetFileType( hDup );

                if ( allHandles )
                {
                    if ( sh.pid != prevPid )
                    {
                        prevPid = sh.pid;
                        map<ULONG_PTR,char *>::iterator iterImage = pidToImage.find( sh.pid );
                        if ( iterImage == pidToImage.end() )
                        {
                            if ( FindProcessPath( hProc, bufferImageName ) )
                                pidToImage[ sh.pid ] = _strdup( bufferImageName.data() );
                            else
                            {
                                if ( verbose )
                                    printf( "can't find process path error %d\n", GetLastError() );
                            }
                        }

                        iterImage = pidToImage.find( sh.pid );
                        if ( iterImage != pidToImage.end() )
                            printf( "pid %llu image: %s\n", sh.pid, iterImage->second );
                        else
                            printf( "pid %llu image: <unavailable>\n", sh.pid );
                    }
    
                    if ( handleTypeFile == sh.objectTypeIndex )
                    {
                        if ( FILE_TYPE_DISK == fileType )
                        {
                            FindFilePath( hDup, bufferPath );
                            char * path = bufferPath.data();
                            if ( !strncmp( path, "\\\\?\\", 4 ) )
                                path += 4;
                            printf( "  %8llu File (disk)                       %s\n", (ULONGLONG) sh.handleValue, path );
                        }
                        else
                            printf( "  %8llu File (%s)\n", (ULONGLONG) sh.handleValue, FileTypeString( fileType ) );
                    }
                    else if ( handleTypeProcess == sh.objectTypeIndex )
                    {
                        FindProcessPath( hDup, bufferImageName );
                        printf( "  %8llu %-33s %s\n", (ULONGLONG) sh.handleValue, HandleTypes[ sh.objectTypeIndex ], bufferImageName.data() );
                    }
                    else
                        printf( "  %8llu %-33s\n", (ULONGLONG) sh.handleValue, HandleTypes[ sh.objectTypeIndex ] );
                }
                else
                {
                    if ( FILE_TYPE_DISK != fileType )
                    {
                        if ( verbose )
                            printf( "  skipping file type %u == %s because it may cause a hang\n", fileType, FileTypeString( fileType ) );
                        continue;
                    }

                    if ( FindFilePath( hDup, bufferPath ) )
                    {
                        char * path = bufferPath.data();
                        if ( !pattern || fstristr( path, pattern ) )
                        {
                            if ( sh.pid != prevPid )
                            {
                                prevPid = sh.pid;
                                map<ULONG_PTR,char *>::iterator iterImage = pidToImage.find( sh.pid );
                                if ( iterImage == pidToImage.end() )
                                {
                                    if ( FindProcessPath( hProc, bufferImageName ) )
                                        pidToImage[ sh.pid ] = _strdup( bufferImageName.data() );
                                    else
                                    {
                                        if ( verbose )
                                            printf( "can't find process path error %d\n", GetLastError() );
                                    }
                                }

                                iterImage = pidToImage.find( sh.pid );
                                if ( iterImage != pidToImage.end() )
                                    printf( "pid %llu image: %s\n", sh.pid, iterImage->second );
                                else
                                    printf( "pid %llu image: <unavailable>\n", sh.pid );
                            }
    
                            if ( !strncmp( path, "\\\\?\\", 4 ) )
                                path += 4;
        
                            printf( "%8llu - %s\n", (ULONGLONG) sh.handleValue, path );
                        }
                    }
                    else if ( verbose )
                        printf( "  pid %llu unable to get path of handle %8llu, error %d\n", sh.pid, (ULONGLONG) sh.handleValue, GetLastError() );
                }
            }
        }
    }

    for ( map<ULONG_PTR,HANDLE>::iterator  it = pidToHandle.begin(); it != pidToHandle.end(); it++ )
        CloseHandle( it->second );

    for ( map<ULONG_PTR,char *>::iterator  it = pidToImage.begin(); it != pidToImage.end(); it++ )
        free( it->second );

    if ( summary )
    {
        size_t total = 0;
        for ( size_t i = 0; i < 256; i++ )
        {
            if ( 0 != handleCounts[ i ] )
            {
                total += handleCounts[ i ];
                printf( "  %33s:  %12zu\n", HandleTypes[ i ], handleCounts[ i ] );
            }
        }
        printf( "total handles: %35zu\n", total );
    }

    return 0;
} //main
