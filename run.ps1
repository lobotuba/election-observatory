# Start the collector and the tracker API as detached background processes.
#   .\run.ps1            start both (stops any previous pair first)
#   .\run.ps1 -Stop      stop both
# Emergency stop of COLLECTION only (API stays up):  New-Item <data dir>\STOP ; delete the file to resume.
param([switch]$Stop)
$data = if ($env:ELECTION_DATA_DIR) { $env:ELECTION_DATA_DIR } else { Join-Path $env:USERPROFILE "electionTracker-data" }
$pidFile = Join-Path $data "pids.txt"
if (Test-Path $pidFile) { Get-Content $pidFile | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue } }
if ($Stop) { "stopped"; return }
$logs = Join-Path $data "logs"; New-Item -ItemType Directory -Force $logs | Out-Null
$py = (Get-Command python).Source; $wd = $PSScriptRoot
$c = Start-Process -FilePath $py -ArgumentList "-m","observatory","collect" -WorkingDirectory $wd -WindowStyle Hidden -RedirectStandardOutput "$logs\collector.out.log" -RedirectStandardError "$logs\collector.err.log" -PassThru
Start-Sleep 6
$s = Start-Process -FilePath $py -ArgumentList "-m","observatory","serve" -WorkingDirectory $wd -WindowStyle Hidden -RedirectStandardOutput "$logs\server.out.log" -RedirectStandardError "$logs\server.err.log" -PassThru
Set-Content $pidFile "$($c.Id)`n$($s.Id)"
"collector pid $($c.Id); tracker http://127.0.0.1:8000 (pid $($s.Id)); logs in $logs"
