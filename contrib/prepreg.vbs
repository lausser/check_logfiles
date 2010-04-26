Dim fragments
Dim objNTInfo
const HKEY_LOCAL_MACHINE = &H80000002
const REG_SZ = 1
const REG_EXPAND_SZ = 2
const REG_BINARY = 3
const REG_DWORD = 4
const REG_MULTI_SZ = 7

argList = ""
Set objArgs = WScript.Arguments
For I = 0 to objArgs.Count - 1
   argList = argList & " " & objArgs(I)
Next

CheckStartMode

Sub CheckStartMode
    strStartExe = UCase( Mid( wscript.fullname,_
    	instrRev(wscript.fullname, "\") + 1 ) )
    If Not strStartExe = "CSCRIPT.EXE" Then
        set objSh = CreateObject("wscript.shell")
        objSh.Run "cscript.exe """ & WScript.scriptFullname & argList & """"
        WScript.quit
    End If
End Sub

Set colNamedArguments = WScript.Arguments.Named
If Not colNamedArguments.Exists("User") Then
    WScript.Echo "Usage: " & WScript.ScriptName & " /USER:Username"
    WScript.Quit(2)
End If

nameParts = Split(colNamedArguments.Item("User"), "\", 2, 1)
If UBound(nameParts) = 1 Then
    strUserName = nameParts(1)
    strDomainName = nameParts(0)
    strQuery = "Select * from Win32_UserAccount Where Name = '" &_
    	strUserName & "' And Domain = '" & strDomainName & "'"
Else
    strUserName = nameParts(0)
    Set objNTInfo = CreateObject("WinNTSystemInfo")
    strDomainName = objNTInfo.ComputerName
    strQuery = "Select * from Win32_UserAccount Where Name = '" &_
    	strUserName & "' And LocalAccount = True"
End If

strComputer = "."

Set objWMIService =_
    GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
Set colItems = objWMIService.ExecQuery(strQuery)
For Each objItem in colItems
    sid = objItem.SID
Next

if sid = "" Then
    WScript.Echo "Could not find SID for user " &_
    	strDomainName & "\" & strUserName
    WScript.Quit(2)
End If

Set objReg = GetObject( _
   "winmgmts:{impersonationLevel=impersonate}!\\" &_
    strComputer & "\root\default:StdRegProv")

strKeyPath = "System\CurrentControlSet\Services\Eventlog\"

Set objShell = WScript.CreateObject("WScript.Shell")
objShell.Run("%windir%\regedit.exe" &_
    " /a " & "%TEMP%\check_logfiles.before.reg" &_
 	" HKEY_LOCAL_MACHINE\" & strKeyPath)

objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, eventlogNames
For I = 0 To UBound(eventlogNames)
    intResult = objReg.GetStringValue(HKEY_LOCAL_MACHINE,_
        strKeyPath & eventlogNames(I), "CustomSD", customSD)
    If intResult = 0 Then
        fragments = Split(customSD, "(", 2, 1)
        prefix = fragments(0)
        remainder = fragments(1)
        rules = Split(remainder, "(", -1, 1)
        found = False
        For x = 0 to UBound(rules)
            rule = Replace(rules(x), ")", "")
            parts = Split(rule, ";", -1, 1)
            If parts(5) = sid Then
                found = True
            End If
        Next
        If found = True Then
            If colNamedArguments.Exists("Del") Then
            ' rauswerfen
            Else
                WScript.Echo strDomainName & "\" & strUserName &_
                    " already had permissions for " & eventlogNames(I)
            End If
        Else
            customSD = customSD & "(A;;0x1;;;" & sid & ")"
            WScript.Echo "c+st of " & strKeyPath & eventlogNames(I) &_
                "\CustomSD" & " is " & customSD
            objReg.SetStringValue HKEY_LOCAL_MACHINE, strKeyPath &_
                eventlogNames(I), "CustomSD", customSD
        End If
    Else
        If Not colNamedArguments.Exists("Del") Then
            WScript.Echo eventlogNames(I) & " has no key CustomSD"
            'not force => anweisung zum selbermachen
            ' argument /AUTO
	    'objReg.CreateKey HKEY_LOCAL_MACHINE, strKeyPath &_
	    '    eventlogNames(I) ???
	    'objReg.SetStringvalue    defheader & "(A;;0x1;;;" & sid & ")"
        End If
    End If 
Next
