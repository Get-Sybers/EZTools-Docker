Description: GoDFIR default batch — high-value persistence/execution/config keys
Author: GoDFIR-toolz (NOT Eric Zimmerman's Kroll_Batch.reb; supply your own with --bn)
Keys:
    -
        Description: Run key (per-machine autostart)
        HiveType: Software
        Category: Persistence
        KeyPath: Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: Programs launched at every login
    -
        Description: RunOnce (per-machine)
        HiveType: Software
        Category: Persistence
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: ""
    -
        Description: Run key (per-user autostart)
        HiveType: NtUser
        Category: Persistence
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: ""
    -
        Description: TypedPaths (Explorer address bar)
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
        Recursive: false
        Comment: ""
    -
        Description: ComputerName
        HiveType: System
        Category: System Config
        KeyPath: ControlSet001\Control\ComputerName\ComputerName
        ValueName: ComputerName
        Recursive: false
        Comment: ""
    -
        Description: TimeZone
        HiveType: System
        Category: System Config
        KeyPath: ControlSet001\Control\TimeZoneInformation
        Recursive: false
        Comment: ""
