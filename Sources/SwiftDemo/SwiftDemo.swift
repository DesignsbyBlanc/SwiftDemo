import WinSDK
import MinHook

typealias CreateFileAType = @convention(c) (
    LPCSTR?,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES?,
    DWORD,
    DWORD,
    HANDLE?
) -> HANDLE?

nonisolated(unsafe) var originalCreateFileA: LPVOID? = nil

let myCreateFileADetour: CreateFileAType = {
    (
        lpFileName: LPCSTR?,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: LPSECURITY_ATTRIBUTES?,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE?
    ) -> HANDLE? in

    guard let originalAddress = originalCreateFileA else {
        print("[Intercept] ERROR: Original CreateFileA trampoline is nil.")
        return INVALID_HANDLE_VALUE
    }

    let originalFunc = unsafeBitCast(
        originalAddress,
        to: CreateFileAType.self
    )

    if let fileNamePtr = lpFileName {
        let nameStr = String(cString: fileNamePtr)

        print("\n[Intercept] CreateFileA invoked for file: '\(nameStr)'")

        if nameStr == "original.txt" {
            let redirectedName = "redirected_path.txt"

            print(
                "[Intercept] Redirecting file creation path to: '\(redirectedName)'"
            )

            return redirectedName.withCString { newPtr in
                originalFunc(
                    newPtr,
                    dwDesiredAccess,
                    dwShareMode,
                    lpSecurityAttributes,
                    dwCreationDisposition,
                    dwFlagsAndAttributes,
                    hTemplateFile
                )
            }
        }
    }

    return originalFunc(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    )
}

@main
struct SwiftDemo {

    static func main() {
        let args = CommandLine.arguments

        if args.contains("--subprocess") {
            runSubprocessTask()
        } else {
            runHostTask()
        }
    }

    static func runHostTask() {
        let hostPid = GetCurrentProcessId()

        print("========================================")
        print("[Host] Host Program PID: \(hostPid)")
        print("========================================")

        print("[Host] Preparing to spawn subprocess...")

        var si = STARTUPINFOW()
        si.cb = DWORD(MemoryLayout<STARTUPINFOW>.size)

        var pi = PROCESS_INFORMATION()

        let currentPath = CommandLine.arguments[0]
        let cmdLine = "\(currentPath) --subprocess"

        var mutableCmdLine = Array(cmdLine.utf16) + [0]

        let success = mutableCmdLine.withUnsafeMutableBufferPointer { ptr in
            CreateProcessW(
                nil,
                ptr.baseAddress,
                nil,
                nil,
                false,
                0,
                nil,
                nil,
                &si,
                &pi
            )
        }

        if success {
            print("[Host] Subprocess created successfully.")
            print("[Host] Subprocess PID: \(pi.dwProcessId)")

            WaitForSingleObject(pi.hProcess, INFINITE)

            CloseHandle(pi.hProcess)
            CloseHandle(pi.hThread)

            print("[Host] Subprocess execution finished. Host exiting.")
        } else {
            print(
                "[Host] Failed to create subprocess. Error code: \(GetLastError())"
            )
        }
    }

    static func runSubprocessTask() {
        let subPid = GetCurrentProcessId()

        print("\n----------------------------------------")
        print("[Subprocess] Subprocess PID: \(subPid)")
        print("[Subprocess] Initializing MinHook...")

        let initResult = MH_Initialize()

        guard initResult == MH_OK else {
            print(
                "[Subprocess] Failed to initialize MinHook. Error code: \(initResult)"
            )
            return
        }

        print(
            "[Subprocess] Data Structure State: MinHook status -> Initialized (MH_OK)"
        )

        guard let kernel32 = GetModuleHandleA("kernel32.dll"),
              let procAddress = GetProcAddress(
                  kernel32,
                  "CreateFileA"
              ) else {

            print("[Subprocess] Failed to locate CreateFileA address.")

            MH_Uninitialize()
            return
        }

        let targetAddr = unsafeBitCast(
            procAddress,
            to: LPVOID.self
        )

        print(
            "[Subprocess] Data Structure State: Target function 'CreateFileA' located at address: \(targetAddr)"
        )

        let detourPtr = unsafeBitCast(
            myCreateFileADetour,
            to: LPVOID.self
        )

        let createResult = MH_CreateHook(
            targetAddr,
            detourPtr,
            &originalCreateFileA
        )

        if createResult == MH_OK {
            print(
                "[Subprocess] Data Structure State: Hook created successfully."
            )

            print(
                "[Subprocess] Data Structure State: Trampoline generated at memory location: \(String(describing: originalCreateFileA))"
            )

            let enableResult = MH_EnableHook(targetAddr)

            if enableResult == MH_OK {
                print(
                    "[Subprocess] Data Structure State: Hook enabled. Function prologue patched with JMP instruction."
                )

                let testFilename = "original.txt"

                print(
                    "[Subprocess] Attempting to create file: '\(testFilename)'..."
                )

                let handle = testFilename.withCString { asciiPtr in
                    CreateFileA(
                        asciiPtr,
                        DWORD(GENERIC_WRITE),
                        0,
                        nil,
                        DWORD(CREATE_ALWAYS),
                        DWORD(FILE_ATTRIBUTE_NORMAL),
                        nil
                    )
                }

                if let h = handle, h != INVALID_HANDLE_VALUE {
                    print(
                        "[Subprocess] Success! File handle acquired. Check local directory for 'redirected_path.txt'."
                    )

                    CloseHandle(h)
                } else {
                    print(
                        "[Subprocess] File creation failed. Error code: \(GetLastError())"
                    )
                }

                MH_DisableHook(targetAddr)

                print(
                    "[Subprocess] Data Structure State: Hook disabled and restored to original state."
                )

            } else {
                print(
                    "[Subprocess] Failed to enable hook. Error code: \(enableResult)"
                )
            }

        } else {
            print(
                "[Subprocess] Failed to create hook. Error code: \(createResult)"
            )
        }

        MH_Uninitialize()

        print(
            "[Subprocess] MinHook uninitialized. Exiting subprocess.\n"
        )
    }
}