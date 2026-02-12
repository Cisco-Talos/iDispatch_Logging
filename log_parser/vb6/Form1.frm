VERSION 5.00
Begin VB.Form Form1 
   Caption         =   "IDispatch Log Post Processor - Reconstruct COM Calls"
   ClientHeight    =   8505
   ClientLeft      =   60
   ClientTop       =   405
   ClientWidth     =   10665
   LinkTopic       =   "Form1"
   ScaleHeight     =   8505
   ScaleWidth      =   10665
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton cmdCopyOut 
      Caption         =   "Copy Output"
      Height          =   375
      Left            =   7020
      TabIndex        =   5
      Top             =   3300
      Width           =   1335
   End
   Begin VB.CommandButton cmdSample 
      Caption         =   "Sample"
      Height          =   375
      Left            =   60
      TabIndex        =   4
      Top             =   3240
      Width           =   1215
   End
   Begin VB.CommandButton cmdPaste 
      Caption         =   "Paste"
      Height          =   375
      Left            =   1500
      TabIndex        =   3
      Top             =   3240
      Width           =   1395
   End
   Begin VB.TextBox txtOut 
      BeginProperty Font 
         Name            =   "Courier"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   4695
      Left            =   0
      MultiLine       =   -1  'True
      ScrollBars      =   3  'Both
      TabIndex        =   2
      Top             =   3780
      Width           =   10635
   End
   Begin VB.CommandButton cmdProcess 
      Caption         =   "Post Process"
      Height          =   375
      Left            =   9240
      TabIndex        =   1
      Top             =   3300
      Width           =   1335
   End
   Begin VB.TextBox txtRaw 
      BeginProperty Font 
         Name            =   "Courier"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   3015
      Left            =   0
      MultiLine       =   -1  'True
      ScrollBars      =   3  'Both
      TabIndex        =   0
      Top             =   120
      Width           =   10635
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
' frmLogProcessor.frm - Debug Log Post-Processor
' Reconstructs script commands from IDispatch proxy logs
' Add: Form with txtRaw (multiline, scrollbars), txtout (multiline, scrollbars), cmdProcess
'
'Copyright: Cisco Talos 2025
'License:   Apache 2.0
'Author:    David Zimmer <dzzie@yahoo.com>

Option Explicit
 

Private Proxies As Collection
Private OutputLines As Collection

Private Sub cmdCopyOut_Click()
    Clipboard.Clear
    Clipboard.SetText txtOut.text
End Sub

Private Sub cmdPaste_Click()
    Dim tmp As String
    tmp = Clipboard.GetText
    txtRaw.text = ""
    txtRaw.SelStart = 0
    ' Use SelText instead of Text
    txtRaw.SelText = tmp 'bypass length limit of .text
    txtOut = Empty
End Sub

Private Sub cmdSample_Click()
    Dim p As String
    p = App.path & "\sample_log.txt"
    If Not FileExists(p) Then p = App.path & "\..\sample_log.txt"
    If Not FileExists(p) Then p = App.path & "\log_reconstructor\sample_log.txt"
    If Not FileExists(p) Then
        MsgBox "Could not find sample_log.txt in ./  ./../ or ./log_reconstructor/", vbExclamation
        Exit Sub
    End If
    txtRaw = ReadFile(p)
End Sub

Private Sub Form_Load()
    Me.Caption = "IDispatch Log Processor"
    cmdProcess.Caption = "&Process Log"
    
    ' Setup text boxes
    txtRaw.Font.Name = "Courier New"
    txtRaw.Font.Size = 9
    txtOut.Font.Name = "Courier New"
    txtOut.Font.Size = 10
    
    ' Sample hint
    txtRaw.text = "Paste debug log here..."
    txtOut.text = "Processed output will appear here..."
End Sub

Private Sub cmdProcess_Click()
    Set Proxies = New Collection
    Set OutputLines = New Collection
    
    ProcessLog txtRaw.text
    
    ' Display results
    Dim output As String
    Dim line As Variant
    For Each line In OutputLines
        output = output & line & vbCrLf
    Next
    
    txtOut.text = output
End Sub

Private Sub ProcessLog(logText As String)
    Dim lines() As String
    Dim i As Long
    Dim line As String
    
    lines = Split(logText, vbCrLf)
    
    For i = 0 To UBound(lines)
        line = Trim(lines(i))
        
        ' Skip empty lines and non-relevant lines
        If Len(line) = 0 Then GoTo NextLine
        If InStr(line, "[INIT]") > 0 Then GoTo NextLine
        If InStr(line, "[SHUTDOWN]") > 0 Then GoTo NextLine
        If InStr(line, "[HOOK]") > 0 Then GoTo NextLine
        If InStr(line, "AddRef:") > 0 Then GoTo NextLine
        If InStr(line, "Release:") > 0 Then GoTo NextLine
        If InStr(line, "QueryInterface:") > 0 Then GoTo NextLine
        If InStr(line, "GetTypeInfo:") > 0 Then GoTo NextLine
        If InStr(line, "[WRAP]") > 0 Then GoTo NextLine
        
        ' Process relevant lines
        If InStr(line, "CLSIDFromProgID") > 0 Then
            ProcessCLSIDFromProgID line
        ElseIf InStr(line, "[PROXY] Created proxy") > 0 Then
            ProcessProxyCreation line
        ElseIf InStr(line, ">>> Invoke:") > 0 Then
            ProcessMethodCall lines, i
        ElseIf InStr(line, "GetIDsOfNames:") > 0 Then
            ' Skip, handled by Invoke
        End If
        
NextLine:
    Next i
End Sub

Private Sub ProcessCLSIDFromProgID(line As String)
    ' Extract ProgID from CLSIDFromProgID
    ' Example: [CLSIDFromProgID] 'Scripting.FileSystemObject' -> {GUID}
    Dim progId As String
    Dim startPos As Long, endPos As Long
    
    startPos = InStr(line, "'")
    If startPos > 0 Then
        endPos = InStr(startPos + 1, line, "'")
        If endPos > startPos Then
            progId = Mid(line, startPos + 1, endPos - startPos - 1)
            OutputLines.Add "CreateObject(""" & progId & """)"
        End If
    End If
End Sub

Private Sub ProcessProxyCreation(line As String)
    ' Track proxy creation
    ' Example: [PROXY] Created proxy #1 for FileSystemObject (Original: 0x...)
    Dim proxyNum As String
    Dim objectName As String
    Dim parts() As String
    Dim proxy As ProxyInfo
    
    If InStr(line, "proxy #") > 0 Then
        parts = Split(line, "#")
        If UBound(parts) >= 1 Then
            parts = Split(parts(1), " ")
            proxyNum = parts(0)
            
            ' Extract object name
            Dim forPos As Long
            forPos = InStr(line, " for ")
            If forPos > 0 Then
                objectName = Mid(line, forPos + 5)
                objectName = Split(objectName, " ")(0)
                
                ' Store proxy info
                Set proxy = New ProxyInfo
                proxy.ProxyID = proxyNum
                proxy.objectName = objectName
                
                On Error Resume Next
                Proxies.Add proxy, "P" & proxyNum
                On Error GoTo 0
            End If
        End If
    End If
End Sub

Private Sub ProcessMethodCall(lines() As String, ByRef lineIndex As Long)
    ' Process method invocation
    ' Example: [PROXY #1] >>> Invoke: FileSystemObject.GetSpecialFolder (METHOD PROPGET ) ArgCount=1
    Dim line As String
    line = lines(lineIndex)
    
    Dim objectMethod As String
    Dim args As Collection
    Dim result As String
    Dim i As Long
    
    ' Extract object.method
    Dim startPos As Long, endPos As Long
    startPos = InStr(line, "Invoke: ")
    If startPos > 0 Then
        startPos = startPos + 8
        endPos = InStr(startPos, line, " (")
        If endPos > 0 Then
            objectMethod = Mid(line, startPos, endPos - startPos)
        End If
    End If
    
    ' Extract method type
    Dim isPropGet As Boolean, isPropPut As Boolean, isMethod As Boolean
    isPropGet = InStr(line, "PROPGET") > 0
    isPropPut = InStr(line, "PROPPUT") > 0
    isMethod = InStr(line, "METHOD") > 0 And Not isPropGet
    
    ' Collect arguments
    Set args = New Collection
    i = lineIndex + 1
    While i <= UBound(lines) And InStr(lines(i), "Arg[") > 0
        Dim argLine As String
        argLine = lines(i)
        
        ' Extract argument value
        Dim colonPos As Long
        colonPos = InStr(argLine, ": ")
        If colonPos > 0 Then
            args.Add Mid(argLine, colonPos + 2)
        End If
        i = i + 1
    Wend
    
    ' Get result if exists
    While i <= UBound(lines) And InStr(lines(i), "<<< Result:") = 0
        i = i + 1
    Wend
    
    If i <= UBound(lines) And InStr(lines(i), "<<< Result:") > 0 Then
        Dim resultLine As String
        resultLine = lines(i)
        startPos = InStr(resultLine, ": ")
        endPos = InStr(resultLine, " (HRESULT")
        If startPos > 0 And endPos > 0 Then
            result = Mid(resultLine, startPos + 2, endPos - startPos - 2)
        End If
    End If
    
    ' Format output
    Dim output As String
    
    ' Simplify object names from proxies
    objectMethod = Replace(objectMethod, "FileSystemObject.GetSpecialFolder.", "")
    
    If isPropGet Then
        ' Property get
        If args.Count = 0 Then
            output = objectMethod
        Else
            ' Method-style property with arguments
            output = objectMethod & "("
            Dim arg As Variant
            Dim first As Boolean
            first = True
            For Each arg In args
                If Not first Then output = output & ", "
                output = output & arg
                first = False
            Next
            output = output & ")"
        End If
        
        If Len(result) > 0 And result <> "(void)" Then
            output = output & "  ' Returns: " & result
        End If
        
    ElseIf isPropPut Then
        ' Property put
        output = objectMethod & " = "
        If args.Count > 0 Then
            output = output & args(args.Count)
        End If
        
    Else
        ' Method call
        output = objectMethod & "("
        Dim arg2 As Variant
        Dim first2 As Boolean
        first2 = True
        For Each arg2 In args
            If Not first2 Then output = output & ", "
            output = output & arg2
            first2 = False
        Next
        output = output & ")"
        
        If Len(result) > 0 And result <> "(void)" Then
            output = output & "  ' Returns: " & result
        End If
    End If
    
    ' Clean up the output
    output = CleanOutput(output)
    
    OutputLines.Add output
    lineIndex = i
End Sub

Private Function CleanOutput(text As String) As String
    ' Clean up the output for better readability
    Dim result As String
    result = text
    
    ' Remove IDispatch: prefixes from results
    result = Replace(result, "IDispatch:", "Object:")
    
    ' Simplify nested object names
    result = Replace(result, "FileSystemObject.", "fso.")
    result = Replace(result, "WScript.Shell.", "shell.")
    result = Replace(result, "Scripting.Dictionary.", "dict.")
    
    ' Format property access better
    If InStr(result, ".GetSpecialFolder") > 0 Then
        result = Replace(result, "GetSpecialFolder(2)", "GetSpecialFolder(TemporaryFolder)")
    End If
    
    CleanOutput = result
End Function

Private Sub Form_Resize()
    On Error Resume Next
    
    ' Make text boxes resize with form
    Dim margin As Long
    margin = 120
    
    txtRaw.Width = Me.ScaleWidth - (margin * 2)
    txtRaw.Height = (Me.ScaleHeight - cmdProcess.Height - margin * 4) / 2
    
    cmdProcess.Top = txtRaw.Top + txtRaw.Height + margin
    cmdProcess.Left = Me.ScaleWidth - cmdProcess.Width - margin
    cmdPaste.Top = cmdProcess.Top
    cmdSample.Top = cmdProcess.Top
    cmdCopyOut.Top = cmdProcess.Top
    
    txtOut.Top = cmdProcess.Top + cmdProcess.Height + margin
    txtOut.Width = txtRaw.Width
    txtOut.Height = Me.Height - txtOut.Top - (margin * 5)
End Sub



Function FileExists(path As String) As Boolean
  On Error GoTo hell
    
  If Len(path) = 0 Then Exit Function
  If Right(path, 1) = "\" Then Exit Function
  If Dir(path, vbHidden Or vbNormal Or vbReadOnly Or vbSystem) <> "" Then FileExists = True
  
  Exit Function
hell: FileExists = False
End Function

Function ReadFile(filename)
  Dim f As Long, temp As String
  f = FreeFile
  temp = ""
   Open filename For Binary As #f        ' Open file.(can be text or image)
     temp = Input(FileLen(filename), #f) ' Get entire Files data
   Close #f
   ReadFile = temp
End Function

