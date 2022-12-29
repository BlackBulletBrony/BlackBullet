# Источник - https://winitpro.ru/index.php/2019/10/02/blokirovka-rdp-atak-firewall-powershell/
# Скрипт собран из разных скриптов в обсуждении источника

$Attempts = 5 # За сколько попыток блокировать
$Hours = 1 # За какое время считать попытки, в часах
$RDPPort = "3389" # Блокируемый порт (стандартный - 3389)
$NameRule = "BlockRDPBruteForce" # Название правила брандмауэра
$log = "C:\Users\Public\blocked_ip_rdp.txt" # Лог-файл для заблокированных IP
$runlog = "C:\Users\Public\runlog.txt" # Лог-файл для информации о запуске скрипта 

# Чисто для проверки запуска скрипта и передачи аргумента
if ($args[0] -match "^t(e?st)?$") {"TeST"
	#"TeST 123" >> $runlog
	return
}

# Пауза перед запуском для сбора неудачных попыток авторизации, передаётся аргументом в секундах (в это время планировщику должно быть запрещено запускать другие копии скрипта)
if($null -ne $args[0]) {
	Wait-Event -Timeout $args[0]
}
# Проверяем наличие правила в брандмауэре и создаём его, если отсутствует
if($null -eq (Get-NetFirewallRule -DisplayName $NameRule -ErrorAction SilentlyContinue)){New-NetFirewallRule -DisplayName "$NameRule" –RemoteAddress 1.1.1.1 -Direction Inbound -Protocol TCP –LocalPort $RDPPort -Action Block}
# Получаем список системных сообщений с неудачными попытками за указанное время
$badRDPlogons = Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational';ID='140';StartTime=([DateTime]::Now.AddHours(-$Hours))}
# Проверяем результат предыдущей команды и если он успешный, то продолжаем
if ($?) {
	# Получаем новые IP адреса с неудачными попытками авторизации за указанное время
	$getip = $badRDPlogons.Properties | Group-Object -property value | Where-Object {$_.Count -gt $Attempts} | Select -property Name
	# Получаем список IP из текущего правила брандмауэра
	$current_ips = (Get-NetFirewallRule -DisplayName "$NameRule" | Get-NetFirewallAddressFilter ).RemoteAddress -split(',')
	# Проверяем найденные IP среди уже заблокированных и формируем итоговый список IP
	$ip = $getip | Where-Object { $getip.Name.Length -gt 1 -and !($current_ips -contains $getip.Name) }
	for ($i = 0; $i -lt @($ip).Count; $i++) {
		$current_ips += $getip[$i].name.Trim()
		# Записываем информацию в лог-файл
		'['+(Get-Date -Format G) + '] IP ' + $ip[$i].name + ' blocked for ' + ($badRDPlogons.Properties | Where-Object {$_.Value -eq $ip[$i].Name}).count + ' unsuccessful attempts in ' + $Hours + ' hour(s).'>> $log
	}
	# Очищаем готовый список IP от дубликатов
	$update_ips = ($current_ips | Group-Object | Select-Object -property Name).name.Trim()
	# Обновляем правило брандмауэра
	Set-NetFirewallRule -DisplayName "$NameRule" -RemoteAddress $update_ips
}
# Лог запусков скрипта
"["+(Get-Date).ToString() + " (-15 min)] IP: $current_ips" >> $runlog

#Write-Host "$current_ips" | Out-GridView

# Получаем список IP из текущего правила брандмауэра
#(Get-NetFirewallRule -DisplayName "BlockRDPBruteForce" | Get-NetFirewallAddressFilter ).RemoteAddress -split(',')

# Обновляем правило брандмауэра
#Set-NetFirewallRule -DisplayName "BlockRDPBruteForce" -RemoteAddress <IP>,<IP2>,...