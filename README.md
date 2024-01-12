# ohandle
Windows command-line app to show handle information

* fully usermode, no device driver required
* due to blocking on pipes, threads are used to query for information
* just one somewhat undocumented call is used

Usage information:

    usage:         ohandle [-p:PID] [-v] [pattern]
      arguments:   -a           All handles, not just disk files
                   -p:PID       Limit results to this PID or binary name prefix
                   -s           Summary handle counts for all or just -p
                   -v           verbose; show errors and progress
                   pattern      case-insensitive disk file filter if not -a or -s
      e.g.:        ohandle -p:6492
                   ohandle adobe
                   ohandle -p:6482 v:
                   ohandle
                   ohandle -s
                   ohandle -s -p:outlook
