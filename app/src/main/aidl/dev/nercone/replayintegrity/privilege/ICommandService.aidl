package dev.nercone.replayintegrity.privilege;

// Runs commands in the process of a privileged service (a Shizuku user service).
interface ICommandService {
    // Called by Shizuku to stop the service. The transaction code is fixed by Shizuku.
    void destroy() = 16777114;

    // Runs `command` without a shell and returns a Bundle with "exitCode" (int),
    // "stdout" (String) and "stderr" (String).
    Bundle execute(in String[] command, long timeoutMillis) = 1;

    // The user ID the service runs as.
    int uid() = 2;
}
