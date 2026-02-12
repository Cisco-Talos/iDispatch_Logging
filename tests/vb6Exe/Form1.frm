VERSION 5.00
Begin VB.Form Form1 
   Caption         =   "vb6 exe late bound com test"
   ClientHeight    =   8265
   ClientLeft      =   60
   ClientTop       =   405
   ClientWidth     =   8115
   LinkTopic       =   "Form1"
   ScaleHeight     =   8265
   ScaleWidth      =   8115
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton Command2 
      Caption         =   "Test OutObj"
      Height          =   375
      Left            =   660
      TabIndex        =   2
      Top             =   7800
      Width           =   2355
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Copy"
      Height          =   375
      Left            =   6540
      TabIndex        =   1
      Top             =   7860
      Width           =   1335
   End
   Begin VB.TextBox Text1 
      BeginProperty Font 
         Name            =   "Courier"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   7695
      Left            =   60
      MultiLine       =   -1  'True
      ScrollBars      =   3  'Both
      TabIndex        =   0
      Top             =   60
      Width           =   7935
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit

Sub t(x)
    Text1 = Text1 & x & vbCrLf
End Sub

Private Sub Command1_Click()
    Clipboard.Clear
    Clipboard.SetText Text1
End Sub

Private Sub Command2_Click()
    
    On Error GoTo hell
    Dim objWMI, objSnapshotService, colVMs, objVM, objInParams, objOutParams, objResultingSnapshot, ComputerName, objProp, objChildObject, objWrappedChild
    
    Text1 = Empty
    
1    Set objWMI = GetObject("winmgmts:\\.\root\default:StdRegProv")
2    Set objInParams = objWMI.Methods_("EnumKey").InParameters.SpawnInstance_
3    objInParams.hDefKey = &H80000002  ' HKEY_LOCAL_MACHINE
4    objInParams.sSubKeyName = "SOFTWARE"
 
5    Set objOutParams = objWMI.ExecMethod_("EnumKey", objInParams)

    t "dumping objInParams.Properties_:"
    For Each objProp In objInParams.Properties_
        t " " & objProp.Name
    Next

    ' The output parameters object is an IWbemClassObject (SWbemObject)
    ' Properties are accessed through the Properties_ collection
    
    ' Method 1: Enumerate all properties
6    For Each objProp In objOutParams.Properties_

         If TypeName(objProp.Value) = "Variant()" Then
            t "Property: " & objProp.Name & " = " & Join(objProp.Value, ",")
         Else
7            t "Property: " & objProp.Name & " = " & objProp.Value
         End If
        
        ' Check if it's an object (CIMType = 13 is "object" or "reference")
8       ' If objProp.CIMType = 13 Then  ' wbemCimtypeObject
        '    ' This property contains an embedded object
9       '     Set objChildObject = objProp.Value
        '     t "  -> Found embedded object!"
        'End If
    Next

Exit Sub
hell:
    t Err.Description & " Line: " & Erl
End Sub

Sub Form_Load()

    Dim wmi As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim obj As Object
    Dim col As Object
    Dim item As Object
    Dim fso As Object
    Dim dict As Object

    
    On Error Resume Next
    
    t "=== Malware WMI Pattern Simulation ==="
    t "This simulates typical malware reconnaissance patterns"
    t ""
    
    ' Pattern 1: System Information Gathering
    t "[RECON] Pattern 1: System Information Gathering"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        
        ' OS Information
        Set colItems = wmi.ExecQuery("SELECT * FROM Win32_OperatingSystem")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  OS: " & objItem.Caption & " Build " & objItem.BuildNumber
                Exit For
            Next
            Set colItems = Nothing
        End If
        
        ' Computer System
        Set colItems = wmi.ExecQuery("SELECT * FROM Win32_ComputerSystem")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  Computer: " & objItem.Name
                t "  Domain: " & objItem.domain
                t "  Manufacturer: " & objItem.Manufacturer
                Exit For
            Next
            Set colItems = Nothing
        End If
        
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    ' Pattern 2: Antivirus Detection
    t "[RECON] Pattern 2: Antivirus Detection"
    Set wmi = GetObject("winmgmts:\\.\root\SecurityCenter2")
    If Err.Number = 0 Then
        Set colItems = wmi.ExecQuery("SELECT * FROM AntiVirusProduct")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  AV Found: " & objItem.DisplayName
                t "  State: " & objItem.productState
            Next
            Set colItems = Nothing
        Else
            t "  No AV products found or query failed"
        End If
        Set wmi = Nothing
    Else
        t "  SecurityCenter2 not accessible (maybe Win7/2008 or earlier)"
    End If
    Err.Clear
    t ""
    
    ' Pattern 3: Running Process Enumeration
    t "[RECON] Pattern 3: Running Process Enumeration"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        Set colItems = wmi.ExecQuery("SELECT Name, ProcessId, ExecutablePath FROM Win32_Process")
        If Err.Number = 0 Then
            Dim procCount As Long
            procCount = 0
            For Each objItem In colItems
                procCount = procCount + 1
                If procCount <= 5 Then ' Just show first 5
                    t "  Process: " & objItem.Name & " (PID: " & objItem.ProcessId & ")"
                End If
            Next
            t "  Total processes found: " & procCount
            Set colItems = Nothing
        End If
        
        Dim procs, proc, i, outParams, owner, user, j, domain
        Set procs = wmi.ExecQuery("SELECT * FROM Win32_Process")
        For i = 1 To procs.Count
            Set proc = procs.ItemIndex(i - 1)
            Set outParams = proc.GetOwner()
            'If TypeName(outParams) <> "Empty" Then
                If outParams.ReturnValue = 0 Then
                    t "  " & proc.Name & " : " & user
                    j = j + 1
                End If
            'End If
            If j > 8 Then Exit For
        Next
        
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    ' Pattern 4: Looking for Security Products
    t "[RECON] Pattern 4: Security Product Detection"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        ' Look for common security processes
        Set colItems = wmi.ExecQuery("SELECT Name FROM Win32_Process WHERE Name LIKE '%defender%' OR Name LIKE '%security%' OR Name LIKE '%antivirus%'")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  Security process: " & objItem.Name
            Next
            Set colItems = Nothing
        End If
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    ' Pattern 5: Network Adapter Information
    t "[RECON] Pattern 5: Network Adapter Information"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        Set colItems = wmi.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  Adapter: " & objItem.Description
                On Error Resume Next
                If IsArray(objItem.IPAddress) Then
                    t "  IP: " & objItem.IPAddress(0)
                End If
                On Error GoTo 0
                Exit For ' Just show first
            Next
            Set colItems = Nothing
        End If
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    ' Pattern 6: User Account Enumeration
    t "[RECON] Pattern 6: User Account Enumeration"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        Set colItems = wmi.ExecQuery("SELECT Name, LocalAccount, Disabled FROM Win32_UserAccount WHERE LocalAccount = True")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  User: " & objItem.Name & " (Disabled: " & objItem.Disabled & ")"
            Next
            Set colItems = Nothing
        End If
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    ' Pattern 7: Disk Information
    t "[RECON] Pattern 7: Disk Information"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        Set colItems = wmi.ExecQuery("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  Drive: " & objItem.DeviceID & " (" & FormatNumber(objItem.Size / 1024 / 1024 / 1024, 2) & " GB)"
            Next
            Set colItems = Nothing
        End If
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    ' Pattern 8: Startup Programs
    t "[RECON] Pattern 8: Startup Programs"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        Set colItems = wmi.ExecQuery("SELECT * FROM Win32_StartupCommand")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  Startup: " & objItem.Name & " -> " & objItem.Command
            Next
            Set colItems = Nothing
        End If
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    ' Pattern 9: Services Enumeration
    t "[RECON] Pattern 9: Critical Services Check"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        Set colItems = wmi.ExecQuery("SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'WinDefend' OR Name = 'wscsvc' OR Name = 'Sense'")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  Service: " & objItem.Name & " State=" & objItem.State & " StartMode=" & objItem.StartMode
            Next
            Set colItems = Nothing
        End If
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    ' Pattern 10: BIOS/Hardware Info
    t "[RECON] Pattern 10: BIOS/Hardware Info (VM Detection)"
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number = 0 Then
        Set colItems = wmi.ExecQuery("SELECT * FROM Win32_BIOS")
        If Err.Number = 0 Then
            For Each objItem In colItems
                t "  BIOS: " & objItem.Manufacturer
                t "  Version: " & objItem.Version
                ' Malware checks for VMware, VirtualBox, etc.
                If InStr(LCase(objItem.Manufacturer), "vmware") > 0 Then
                    t "  ** VMware detected **"
                End If
                Exit For
            Next
            Set colItems = Nothing
        End If
        Set wmi = Nothing
    End If
    Err.Clear
    t ""
    
    t "=== VB6 Late Bound CreateObject Tests ==="
    t ""
    
    ' Test 1: FileSystemObject
    t "Test 1: Creating Scripting.FileSystemObject"
    Set fso = CreateObject("Scripting.FileSystemObject")
    If Err.Number = 0 Then
        t "  Success! DriveExists('C:') = " & fso.DriveExists("C:")
        Set fso = Nothing
    Else
        t "  Error: " & Err.Description
    End If
    Err.Clear
    t ""
    
    ' Test 2: Dictionary
    t "Test 2: Creating Scripting.Dictionary"
    Set dict = CreateObject("Scripting.Dictionary")
    If Err.Number = 0 Then
        dict.Add "key1", "value1"
        dict.Add "key2", "value2"
        t "  Success! Dictionary has " & dict.Count & " items"
        t "  key1 = " & dict("key1")
        Set dict = Nothing
    Else
        t "  Error: " & Err.Description
    End If
    Err.Clear
    t ""
    
    ' Test 3: WScript.Shell
    t "Test 3: Creating WScript.Shell"
    Set obj = CreateObject("WScript.Shell")
    If Err.Number = 0 Then
        t "  Success! Computer name = " & obj.ExpandEnvironmentStrings("%COMPUTERNAME%")
        Set obj = Nothing
    Else
        t "  Error: " & Err.Description
    End If
    Err.Clear
    t ""
    
    ' Test 4: XMLHTTP
    t "Test 4: Creating MSXML2.XMLHTTP"
    Set obj = CreateObject("MSXML2.XMLHTTP")
    If Err.Number = 0 Then
        t "  Success! XMLHTTP object created"
        Set obj = Nothing
    Else
        t "  Error: " & Err.Description
    End If
    Err.Clear
    t ""
    
    ' Test 5: ADODB.Connection
    t "Test 5: Creating ADODB.Connection"
    Set obj = CreateObject("ADODB.Connection")
    If Err.Number = 0 Then
        t "  Success! Connection version = " & obj.Version
        Set obj = Nothing
    Else
        t "  Error: " & Err.Description
    End If
    Err.Clear
    t ""
    
    t "=== All Malware Patterns Complete ==="
    t ""
    t "Check your logger output for complete WMI query visibility!"
    
End Sub

