# Build instructions for API-hooking demo based on MinHook

### Instructions:

1. `git clone https://github.com/DesignsbyBlanc/SwiftDemo.git`
2. `cd SwiftDemo`
3. Install vcpkg and MinHook

   ```cmd
    git clone https://github.com/microsoft/vcpkg

    .\vcpkg\bootstrap-vcpkg.bat

    .\vcpkg\vcpkg integrate install

    .\vcpkg\vcpkg install minhook
   ```
4. Update environment variables and MinHook references to the appropriate URIs
5. `swift run SwiftDemo`

### Understanding this repo:

#### Directory Structure:

`C:\stuff\SwiftDemo\`

```
SwiftDemo
├── .build
├── .vscode
├── Sources
│   ├── MinHook
│   │   └── module.modulemap
│   └── SwiftDemo
│       └── SwiftDemo.swift
├── Tests
│   └── SwiftDemoTests
│       └── SwiftDemoTests.swift
├── vcpkg
│   └── packages
│       └── minhook_x64-windows
│           ├── bin
│           ├── include
│           │   └── MinHook.h
│           └── lib
│               └── minhook.x64.lib
├── .gitignore
├── Package.swift
├── build_instructions.md
└── README.md

```

---

#### Environment variables:

```pwsh

$env:PATH = "C:\stuff\SwiftDemo\vcpkg\packages\minhook_x64-windows\bin;$env:PATH"

```

---

#### SwiftDemo.swift:

`C:\stuff\SwiftDemo\Sources\SwiftDemo\SwiftDemo.swift`

```swift
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

```

---

#### Package.swift:

`C:\stuff\SwiftDemo\Package.swift`

```swift
// swift-tools-version: 6.3

import PackageDescription

let package = Package(
    name: "SwiftDemo",
    targets: [
        .systemLibrary(
            name: "MinHook"
        ),

        .executableTarget(
            name: "SwiftDemo",
            dependencies: [
                "MinHook"
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-LC:/stuff/SwiftDemo/vcpkg/packages/minhook_x64-windows/lib"
                ]),
                .linkedLibrary("kernel32"),
            ]
        ),

        .testTarget(
            name: "SwiftDemoTests",
            dependencies: [
                "SwiftDemo"
            ]
        ),
    ],
    swiftLanguageModes: [
        .v6
    ]
)



```

---

#### module.modulemap:

`C:\stuff\SwiftDemo\Sources\MinHook\module.modulemap`

```
module MinHook [system] {
    header "C:/stuff/SwiftDemo/vcpkg/packages/minhook_x64-windows/include/MinHook.h"
    link "minhook.x64"
    export *
}
```

#### Output:

```pwsh

PS C:\stuff\SwiftDemo> swift run SwiftDemo                                                              
[1/1] Planning build
Building for debugging...
[1/1] Write swift-version--5AF7BF7FE8A6AD6B.txt
Build of product 'SwiftDemo' complete! (0.90s)
========================================
[Host] Host Program PID: 54628
========================================
[Host] Preparing to spawn subprocess...
[Host] Subprocess created successfully.
[Host] Subprocess PID: 13300

----------------------------------------
[Subprocess] Subprocess PID: 13300
[Subprocess] Initializing MinHook...
[Subprocess] Data Structure State: MinHook status -> Initialized (MH_OK)
[Subprocess] Data Structure State: Target function 'CreateFileA' located at address: 0x00007ff9547970a0
[Subprocess] Data Structure State: Hook created successfully.
[Subprocess] Data Structure State: Trampoline generated at memory location: Optional(0x00007ff9546f0fc0)
[Subprocess] Data Structure State: Hook enabled. Function prologue patched with JMP instruction.
[Subprocess] Attempting to create file: 'original.txt'...

[Intercept] CreateFileA invoked for file: 'original.txt'
[Intercept] Redirecting file creation path to: 'redirected_path.txt'
[Subprocess] Success! File handle acquired. Check local directory for 'redirected_path.txt'.
[Subprocess] Data Structure State: Hook disabled and restored to original state.
[Subprocess] MinHook uninitialized. Exiting subprocess.

[Host] Subprocess execution finished. Host exiting.
PS C:\stuff\SwiftDemo> 

```



