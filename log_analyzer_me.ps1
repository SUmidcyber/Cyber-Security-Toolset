<#
=== GELİŞMİŞ LOG ANALİZ VE SİBER GÜVENLİK ARAÇ SETİ ===
PowerShell ile geliştirilmiş kapsamlı log analiz ve güvenlik tarama aracı
#>

# Hata ayıklama ve loglama için fonksiyon
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    $logEntry | Out-File -Append -FilePath "security_analysis.log"
}

# JSON export için global değişken
$global:analysisResults = @{}

# Sistem Hata Logları Analizi
function Analyze-SystemLogs {
    Write-Log "Starting system error log analysis..."
    $systemErrors = Get-WinEvent -LogName "System" -ErrorAction SilentlyContinue | Where-Object { $_.Level -eq 2 }
    
    $errorSummary = @{}
    foreach ($error in $systemErrors) {
        $errorId = $error.Id
        if ($errorSummary.ContainsKey($errorId)) {
            $errorSummary[$errorId].Count++
            $errorSummary[$errorId].LastOccurrence = $error.TimeCreated
        } else {
            $errorSummary[$errorId] = @{
                Count = 1
                Message = $error.Message
                FirstOccurrence = $error.TimeCreated
                LastOccurrence = $error.TimeCreated
            }
        }
    }
    
    $global:analysisResults.SystemLogAnalysis = $errorSummary
    Write-Log "System error log analysis completed. Total errors: $($systemErrors.Count)"
    return $errorSummary
}

# Brute Force Saldırı Tespiti
function Detect-BruteForce {
    Write-Log "Initiating Brute Force attack detection..."
    $failedLogins = Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4625]]" -ErrorAction SilentlyContinue
    
    $attackAttempts = @{}
    foreach ($event in $failedLogins) {
        $ip = $event.Properties[19].Value
        $username = $event.Properties[5].Value
        
        if ($attackAttempts.ContainsKey($ip)) {
            $attackAttempts[$ip].Attempts++
            $attackAttempts[$ip].Usernames += $username
        } else {
            $attackAttempts[$ip] = @{
                Attempts = 1
                Usernames = @($username)
                FirstAttempt = $event.TimeCreated
                LastAttempt = $event.TimeCreated
            }
        }
    }
    
    # Şüpheli IP'leri belirleme (5 dakikada 5'ten fazla başarısız giriş)
    $suspiciousIPs = $attackAttempts.GetEnumerator() | Where-Object { 
        $_.Value.Attempts -ge 5 -and 
        ($_.Value.LastAttempt - $_.Value.FirstAttempt).TotalMinutes -le 5 
    }
    
    $global:analysisResults.BruteForceDetection = @{
        AllFailedAttempts = $attackAttempts
        SuspiciousIPs = $suspiciousIPs
    }
    
    Write-Log "Brute Force analysis completed. Number of suspicious IPs: $($suspiciousIPs.Count)"
    return @{
        AllFailedAttempts = $attackAttempts
        SuspiciousIPs = $suspiciousIPs
    }
}

# Process Injection Analizi
function Analyze-ProcessInjection {
    Write-Log "Starting Process Injection analysis..."
    $suspiciousProcesses = Get-Process | Where-Object {
        $_.Modules | Where-Object { 
            $_.ModuleName -like "*dll" -and 
            $_.FileName -notmatch "system32|syswow64" 
        }
    }
    
    $injectionDetails = @()
    foreach ($proc in $suspiciousProcesses) {
        $modules = $proc.Modules | Where-Object { $_.FileName -notmatch "system32|syswow64" }
        foreach ($mod in $modules) {
            $injectionDetails += @{
                ProcessName = $proc.ProcessName
                ProcessID = $proc.Id
                ModuleName = $mod.ModuleName
                ModulePath = $mod.FileName
            }
        }
    }
    
    $global:analysisResults.ProcessInjectionAnalysis = $injectionDetails
    Write-Log "Process Injection analysis completed. Number of suspicious processes: $($injectionDetails.Count)"
    return $injectionDetails
}

# Oturum Açma Kayıtları
function Analyze-LogonEvents {
    Write-Log "Starting login log analysis..."
    $logonEvents = Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4624]]" -ErrorAction SilentlyContinue
    
    $logonSummary = @()
    foreach ($event in $logonEvents) {
        $logonSummary += @{
            Time = $event.TimeCreated
            User = $event.Properties[5].Value
            IP = $event.Properties[19].Value
            LogonType = $event.Properties[8].Value
        }
    }
    
    $global:analysisResults.LogonEvents = $logonSummary
    Write-Log "Login log analysis completed. Total logins: $($logonEvents.Count)"
    return $logonSummary
}

# Zararlı Yazılım Taraması
function Scan-Malware {
    Write-Log "Starting malware scan..."
    # Bilinen kötü amaçlı yazılım işaretleri
    $malwareSignatures = @(
        "cmd.exe /c", "powershell -nop -w hidden", "certutil -decode", 
        "regsvr32 /s /n /u /i:", "mshta.exe", "wscript.shell"
    )
    
    # Şüpheli işlemler
    $suspiciousProcesses = Get-Process | Where-Object {
        $_.CommandLine -ne $null -and 
        ($malwareSignatures | Where-Object { $_.CommandLine -match $_ })
    }
    
    # Şüpheli dosyalar (genellikle kötü amaçlı yazılımların saklandığı yerler)
    $suspiciousLocations = @(
        "$env:APPDATA\*.exe",
        "$env:LOCALAPPDATA\Temp\*.exe",
        "$env:USERPROFILE\Downloads\*.exe",
        "$env:USERPROFILE\Documents\*.scr"
    )
    
    $suspiciousFiles = @()
    foreach ($location in $suspiciousLocations) {
        $files = Get-ChildItem -Path $location -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $suspiciousFiles += @{
                FileName = $file.Name
                Path = $file.FullName
                Size = $file.Length
                LastWriteTime = $file.LastWriteTime
            }
        }
    }
    
    $global:analysisResults.MalwareScan = @{
        SuspiciousProcesses = $suspiciousProcesses
        SuspiciousFiles = $suspiciousFiles
    }
    
    Write-Log "Malware shutdown completed. Suspicious process: $($suspiciousProcesses.Count), Suspicious file: $($suspiciousFiles.Count)"
    return @{
        SuspiciousProcesses = $suspiciousProcesses
        SuspiciousFiles = $suspiciousFiles
    }
}

# Ağ Bağlantı Analizi
function Analyze-NetworkConnections {
    Write-Log "Starting network connectivity analysis..."
    $networkConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
    
    $connectionDetails = @()
    foreach ($conn in $networkConnections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $connectionDetails += @{
            LocalAddress = $conn.LocalAddress
            LocalPort = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort = $conn.RemotePort
            ProcessName = $process.Name
            ProcessID = $conn.OwningProcess
        }
    }
    
    $global:analysisResults.NetworkConnections = $connectionDetails
    Write-Log "Network connection analysis completed. Active connection: $($networkConnections.Count)"
    return $connectionDetails
}

# Zamanlanmış Görev Analizi
function Analyze-ScheduledTasks {
    Write-Log "Starting scheduled task analysis..."
    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
    
    $taskDetails = @()
    foreach ($task in $tasks) {
        $taskDetails += @{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            Author = $task.Author
            Description = $task.Description
            Actions = $task.Actions
            Triggers = $task.Triggers
        }
    }
    
    $global:analysisResults.ScheduledTasks = $taskDetails
    Write-Log "Scheduled mission analysis completed. Active mission: $($tasks.Count)"
    return $taskDetails
}

# Kullanıcı Aktivite Raporu
function Generate-UserActivityReport {
    Write-Log "Generating user activity report..."
    $events = Get-WinEvent -LogName "Security" -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Id -in @(4624, 4634, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726)
    }
    
    $userActivities = @()
    foreach ($event in $events) {
        $activity = @{
            Time = $event.TimeCreated
            EventID = $event.Id
            User = $event.Properties[0].Value
            Description = $event.Message
        }
        $userActivities += $activity
    }
    
    $global:analysisResults.UserActivities = $userActivities
    Write-Log "User activity report completed. Total events: $($events.Count)"
    return $userActivities
}

# Registry Değişiklik Kontrolü
function Check-RegistryChanges {
    Write-Log "Starting Registry change check..."
    # Önemli registry anahtarları
    $importantKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    )
    
    $registryValues = @()
    foreach ($key in $importantKeys) {
        if (Test-Path $key) {
            $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            foreach ($value in $values.PSObject.Properties | Where-Object { $_.MemberType -eq "NoteProperty" }) {
                $registryValues += @{
                    Key = $key
                    Name = $value.Name
                    Value = $value.Value
                }
            }
        }
    }
    
    $global:analysisResults.RegistryValues = $registryValues
    Write-Log "Registry change check completed. Total value: $($registryValues.Count)"
    return $registryValues
}

# Hash Doğrulama Sistemi
function Verify-FileHashes {
    param (
        [string]$Directory = "C:\Windows\System32"
    )
    
    Write-Log "Starting file hash verification. Directory: $Directory"
    $files = Get-ChildItem -Path $Directory -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @(".exe", ".dll", ".sys") }
    
    $fileHashes = @()
    foreach ($file in $files) {
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($hash) {
            $fileHashes += @{
                FileName = $file.Name
                Path = $file.FullName
                Hash = $hash.Hash
            }
        }
    }
    
    $global:analysisResults.FileHashes = $fileHashes
    Write-Log "File hash verification completed. Total files: $($files.Count)"
    return $fileHashes
}

# Tüm Analizleri Çalıştır
function Run-AllAnalyses {
    Write-Log "All analysis is starting..."
    
    Analyze-SystemLogs | Out-Null
    Detect-BruteForce | Out-Null
    Analyze-ProcessInjection | Out-Null
    Analyze-LogonEvents | Out-Null
    Scan-Malware | Out-Null
    Analyze-NetworkConnections | Out-Null
    Analyze-ScheduledTasks | Out-Null
    Generate-UserActivityReport | Out-Null
    Check-RegistryChanges | Out-Null
    Verify-FileHashes | Out-Null
    
    Write-Log "All analyses were completed successfully."
    return $global:analysisResults
}

# Sonuçları JSON Olarak Dışa Aktar
function Export-ToJson {
    param (
        [string]$FilePath = "security_analysis_results.json"
    )
    
    if (-not $global:analysisResults -or $global:analysisResults.Count -eq 0) {
        Write-Log "No data found to export. Run analysis first." -Level "WARNING"
        return $false
    }
    
    try {
        $global:analysisResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath
        Write-Log "Results exported successfully: $FilePath"
        return $true
    } catch {
        Write-Log "JSON export error: $_" -Level "ERROR"
        return $false
    }
}

# Ana menü
function Show-Menu {
    Clear-Host
    Write-Host "=== ADVANCED LOG ANALYSIS AND CYBER SECURITY TOOLSET ==="
    Write-Host "1. System Error Log Analysis"
    Write-Host "2. Brute Force Attack Detection"
    Write-Host "3. Process Injection Analysis"
    Write-Host "4. Login Records"
    Write-Host "5. Malware Scanning"
    Write-Host "6. Network Connection Analysis"
    Write-Host "7. Scheduled Task Analysis"
    Write-Host "8. User Activity Report"
    Write-Host "9. Registry Change Control"
    Write-Host "10. Hash Verification System"
    Write-Host "11. Run All Analysis"
    Write-Host "12. Export Results as JSON"
    Write-Host "e. Exit"
    Write-Host ""
}

# Ana program döngüsü
function Main {
    do {
        Show-Menu
        $selection = Read-Host "Please enter an option (1-12) | Exit (e)"
        
        switch ($selection) {
            '1' { 
                $results = Analyze-SystemLogs
                $results | Format-Table -AutoSize | Out-Host
                Pause
            }
            '2' { 
                $results = Detect-BruteForce
                $results.SuspiciousIPs | Format-Table -AutoSize | Out-Host
                Pause
            }
            '3' { 
                $results = Analyze-ProcessInjection
                $results | Format-Table -AutoSize | Out-Host
                Pause
            }
            '4' { 
                $results = Analyze-LogonEvents
                $results | Format-Table -AutoSize | Out-Host
                Pause
            }
            '5' { 
                $results = Scan-Malware
                $results.SuspiciousFiles | Format-Table -AutoSize | Out-Host
                Pause
            }
            '6' { 
                $results = Analyze-NetworkConnections
                $results | Format-Table -AutoSize | Out-Host
                Pause
            }
            '7' { 
                $results = Analyze-ScheduledTasks
                $results | Select-Object TaskName, Author | Format-Table -AutoSize | Out-Host
                Pause
            }
            '8' { 
                $results = Generate-UserActivityReport
                $results | Format-Table -AutoSize | Out-Host
                Pause
            }
            '9' { 
                $results = Check-RegistryChanges
                $results | Format-Table -AutoSize | Out-Host
                Pause
            }
            '10' { 
                $results = Verify-FileHashes
                $results | Select-Object FileName, Hash | Format-Table -AutoSize | Out-Host
                Pause
            }
            '11' { 
                $results = Run-AllAnalyses
                Write-Host "All analysis is complete. Use JSON export to view results."
                Pause
            }
            '12' { 
                $success = Export-ToJson
                if ($success) {
                    Write-Host "Results exported successfully."
                } else {
                    Write-Host "Export failed."
                }
                Pause
            }
            'e' { 
                Write-Host "Exit in progress..."
                return
            }
            default {
                Write-Host "Invalid option. Please enter a number between 1-13."
                Pause
            }
        }
    } while ($true)
}

# Programı başlat
Main