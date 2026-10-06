# Embedded in the signed Setup.ps1; never sourced from a Client Bundle.
function P6Argument([string]$Value) {
    # Windows CommandLineToArgvW quoting; data never becomes PowerShell code.
    return '"' + [regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1') + '"'
}
function Invoke-P6Backend([string]$Action,[string]$SelectedProfile,[string]$SelectedBundle,[bool]$Auto,$Credential) {
    $credentialPath = $null
    $credentialStage = $null
    $process = $null
    $answer = @{ok=$false; kind='operation'}
    try {
        $items = @('-I','-B',$script:p6Entry,$Action,'--package',$script:p6Package)
        if ($SelectedProfile) { $items += @('--profile',$SelectedProfile) }
        if ($SelectedBundle) { $items += @('--bundle',$SelectedBundle) }
        if ($Auto) { $items += '--discover-controller' }
        if ($null -ne $Credential) {
            $credentialStage = Join-Path $script:p6Common ('P6Credential-' + [Guid]::NewGuid().ToString('N'))
            ProtectedDirectory $credentialStage
            $credentialPath = Join-Path $credentialStage 'mihomo.key'
            $bytes = [Text.Encoding]::UTF8.GetBytes($Credential)
            try {
                if ($bytes.Length -gt 4096 -or $Credential -match '[\x00-\x1f\x7f]') { throw 'credential capacity' }
                [IO.File]::WriteAllBytes($credentialPath,$bytes)
            } finally { [Array]::Clear($bytes,0,$bytes.Length); $Credential = $null }
            $items += @('--controller-key-file',$credentialPath)
        }
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $script:p6Python
        $start.Arguments = (@($items | ForEach-Object { P6Argument ([string]$_) }) -join ' ')
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.StandardOutputEncoding = [Text.Encoding]::UTF8
        $start.StandardErrorEncoding = [Text.Encoding]::UTF8
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $start
        [void]$process.Start()
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        while (-not $process.HasExited) {
            # Keep the window painting; all mutation/refresh handlers are gated
            # by busy. Never kill a service/installer to cancel a durable commit.
            [Windows.Forms.Application]::DoEvents()
            [Threading.Thread]::Sleep(50)
        }
        $stdout = $output.Result
        $stderr = $errors.Result
        if ($stdout.Length -gt 65536 -or $stderr.Length -gt 8192) { throw 'output capacity' }
        if ($process.ExitCode -ne 0) {
            $kind = if ($stderr.Trim() -eq '[FAIL] local_controller_discovery_unavailable') {'discovery'} else {'operation'}
            $answer.kind=$kind
            return $answer
        }
        if (-not $stdout.StartsWith('[PASS] ')) { throw 'output format' }
        $answer.value=(ConvertFrom-Json $stdout.Substring(7) -ErrorAction Stop)
        $answer.ok=$true
        return $answer
    } catch { return $answer }
    finally {
        if ($process) { $process.Dispose() }
        if ($credentialStage) {
            try {
                RealPath $credentialStage
                if ($credentialPath -and (Test-Path -LiteralPath $credentialPath)) {
                    RealPath $credentialPath
                    Remove-Item -LiteralPath $credentialPath -Force -ErrorAction Stop
                }
                Remove-Item -LiteralPath $credentialStage -Force -ErrorAction Stop
            } catch { $answer.ok=$false; $answer.kind='cleanup' }
        }
    }
}
function P6Token($Value) {
    switch ([string]$Value) {
        'ok' {'正常'} 'timeout' {'超时'} 'unavailable' {'不可用'} 'invalid' {'配置无效'}
        'failed' {'失败'} 'active_delay' {'主动测试'} 'passive_cache' {'缓存观察'}
        'reality' {'Reality'} 'hy2' {'Hysteria2'}
        'NONE' {'无错误'}
        'sharing_violation' {'文件暂被占用'}
        'permission_denied' {'写入权限不足'}
        'disk_full' {'磁盘空间不足'}
        'io_error' {'本地读写失败'}
        'state_invalid' {'本地状态无效'}
        default {if ([string]$Value -match '^[A-Za-z0-9_-]{1,64}$') {[string]$Value} else {'未知'}}
    }
}
function Add-P6Row([string]$Metric,[string]$State,[string]$Detail) {
    [void]$script:p6Grid.Rows.Add($Metric,$State,$Detail)
}
function Update-P6Selection {
    $script:p6Grid.Rows.Clear()
    $index = $script:p6Profiles.SelectedIndex
    $live = $false
    $retired = $false
    if ($index -ge 0 -and $index -lt $script:p6Entries.Count) {
        $entry = $script:p6Entries[$index]
        $live = $entry.live
        $retired = -not $live
        if ($live) {
            $profile = $entry.value
            $d=$profile.display
            $client=if ($d.client) {$d.client} else {'未命名客户端（旧配置）'}
            $device=if ($d.device) {$d.device} else {'未命名设备（旧配置）'}
            $location=if ($d.location) {$d.location} else {'未设置'}
            $network=if ($d.network_path) {$d.network_path} else {'未设置'}
            $script:p6Details.Text='客户端：'+$client+' / 设备：'+$device+"`r`n位置："+$location+' / 网络路径：'+$network
            if ($profile.spool) {
                $s = $profile.spool
                Add-P6Row '已确认上传' ([string]$s.acknowledged_total) 'accepted 或 duplicate 的本机确认总数'
                Add-P6Row '尚未解决的记录跨度' ([string]$s.unresolved_record_span) '不是精确待上传条数'
                Add-P6Row '正在重试的记录' ([string]$s.tracked_retry_records) ''
                Add-P6Row '已隔离 / 过期 / 容量丢弃' "$($s.quarantined_total) / $($s.expired_total) / $($s.budget_dropped_total)" ''
                $storageNote='累计次数，不表示当前仍在失败'
                if ($s.PSObject.Properties['storage_diagnostics'] -and $s.storage_diagnostics) {
                    $storageNote+='；最近原因：'+(P6Token $s.storage_diagnostics.last_failure)
                    Add-P6Row '文件占用重试' ([string]$s.storage_diagnostics.sharing_retries) '累计次数，最多两次短暂重试'
                } elseif ($s.state_save_failures -gt 0) {$storageNote+='；旧版本未记录原因'}
                Add-P6Row '损坏 / 状态写入失败' "$($s.corrupt_total) / $($s.state_save_failures)" $storageNote
            } else {Add-P6Row '上传计数' '暂时无状态文件' ''}
            if ($profile.sample) {
                $sample = $profile.sample
                $time = [DateTimeOffset]::FromUnixTimeSeconds([long][Math]::Floor($sample.sample_epoch)).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                Add-P6Row '最近本地采样' $time ('seq=' + $sample.seq)
                foreach ($slot in @(@('DNS','dns'),@('HTTPS','https'),@('VPS TCP','vps_tcp'))) {
                    $value = $sample.($slot[1])
                    $delay = if ($null -ne $value.latency_ms) {[string]$value.latency_ms + ' ms'} else {P6Token $value.error_code}
                    Add-P6Row $slot[0] (P6Token $value.status) $delay
                }
                $egressDetail=if ($sample.egress_status -eq 'ok' -and $null -ne $sample.egress_latency_ms) {
                    [string]$sample.egress_latency_ms + ' ms'
                } elseif ($sample.PSObject.Properties['egress_error_code']) {P6Token $sample.egress_error_code} else {''}
                Add-P6Row '本机出口检测' (P6Token $sample.egress_status) $egressDetail
                $egressIp=if ($sample.PSObject.Properties['egress_ip'] -and $sample.egress_ip) {[string]$sample.egress_ip} else {'未获取'}
                Add-P6Row '本机网络出口 IP' $egressIp ('本次请求的出口；采样：'+$time)
                Add-P6Row 'Clash API' (P6Token $sample.mihomo_api.status) ''
                foreach ($value in @($sample.active)) {
                    $delay = if ($null -ne $value.delay_ms) {[string]$value.delay_ms + ' ms'} else {'—'}
                    Add-P6Row ((P6Token $value.role) + ' / ' + (P6Token $value.source)) (P6Token $value.outcome) $delay
                }
            } else {Add-P6Row '最近本地采样' '暂时无可读取样本' '样本可能尚未生成或已清理'}
        } else {$script:p6Details.Text='已移除设备，本机密钥和队列仍保留。内部标识可在技术详情查看。'}
    } else {$script:p6Details.Text='请选择一个设备查看本地状态。'}
    foreach ($action in @('pause','resume','remove')) {$script:p6Buttons[$action].Enabled=$live -and -not $script:p6Busy -and -not $script:p6Pending}
    $script:p6Buttons['purge'].Enabled=$retired -and -not $script:p6Busy -and -not $script:p6Pending
}
function Refresh-P6Status {
    if ($script:p6Busy) {return}
    $script:p6Busy=$true
    $script:p6Autostart.Enabled=$false
    try {
        $result = Invoke-P6Backend 'ui-status' '' '' $false $null
        if (-not $result.ok) {throw 'snapshot unavailable'}
        $status = $result.value
        $script:p6Pending=[bool]$status.pending_recovery
        $knownStartup=$status.installed -and -not $script:p6Pending -and $status.autostart -is [bool]
        $script:p6Autostart.Checked=$knownStartup -and $status.autostart
        $script:p6Autostart.Enabled=$knownStartup
        $script:p6StartupNote.Text=if ($knownStartup) {
            $(if ($status.autostart) {'已开启'} else {'已关闭'})+'；下次开机生效，当前运行状态不变'
        } else {'安装完成并读取状态后可设置'}
        $selected = if ($script:p6Profiles.SelectedIndex -ge 0 -and $script:p6Profiles.SelectedIndex -lt $script:p6Entries.Count) {$script:p6Entries[$script:p6Profiles.SelectedIndex].id} else {''}
        $script:p6Entries=@()
        $script:p6Profiles.Items.Clear()
        foreach ($profile in @($status.profiles)) {
            $script:p6Entries+=@{id=$profile.id; live=$true; value=$profile}
            [void]$script:p6Profiles.Items.Add($(if ($profile.enabled) {'已启用'} else {'已暂停'}) + ' · ' + $(if ($profile.display.device) {$profile.display.client+' / '+$profile.display.device} else {'旧设备 '+$script:p6Entries.Count}))
        }
        foreach ($id in @($status.retired)) {
            $script:p6Entries+=@{id=$id; live=$false; value=$null}
            [void]$script:p6Profiles.Items.Add('已移除设备（数据保留） '+$script:p6Entries.Count)
        }
        for ($i=0; $i -lt $script:p6Entries.Count; $i++) {if ($script:p6Entries[$i].id -eq $selected) {$script:p6Profiles.SelectedIndex=$i}}
        if ($script:p6Profiles.SelectedIndex -lt 0 -and $script:p6Entries.Count -gt 0) {$script:p6Profiles.SelectedIndex=0}
        if ($script:p6Pending) {$script:p6Heading.Text='存在未完成的安装操作。请明确点击“安装 / 更新”或“回滚”。状态刷新不会自动恢复。'}
        elseif ($status.installed) {
            $state = switch ([int]$status.service_state) {0 {'未注册'} 1 {'已停止'} 4 {'运行中'} 7 {'已暂停'} default {'转换中'}}
            $script:p6Heading.Text='客户端后台服务：' + $state
        } else {$script:p6Heading.Text='尚未安装客户端。选择设备配置后点击“安装 / 更新”。'}
        $script:p6Buttons['import'].Enabled=[bool]$status.installed -and -not $script:p6Pending
        $script:p6Buttons['uninstall'].Enabled=[bool]$status.installed -and @($status.profiles).Count -eq 0 -and -not $script:p6Pending
        $script:p6Buttons['rollback'].Enabled=[bool]$status.installed -or $script:p6Pending
        $cadence=60
        if ($script:p6Profiles.SelectedIndex -ge 0) {
            $selectedValue=$script:p6Entries[$script:p6Profiles.SelectedIndex].value
            if ($selectedValue -and $selectedValue.PSObject.Properties['cadence_seconds']) {$cadence=$selectedValue.cadence_seconds}
        }
        $script:p6Notice.Text='状态每 15 秒刷新，采样间隔 '+$cadence+' 秒；刷新不会立即检测或上传。最后刷新：'+[DateTime]::Now.ToString('HH:mm:ss')+'。本机确认不替代 VPS 入库核对。'
    } catch {
        $script:p6Heading.Text='暂时无法读取状态，请稍后刷新。现有服务和队列未被刷新操作修改。'
        $script:p6Pending=$true
        $script:p6Autostart.Enabled=$false
        $script:p6StartupNote.Text='暂时无法读取开机设置，请刷新后再试'
        foreach ($action in @('import','uninstall','pause','resume','remove','purge')) {$script:p6Buttons[$action].Enabled=$false}
    } finally {$script:p6Busy=$false; Update-P6Selection}
}
function Get-P6ManualCredential {
    $dialog = New-Object Windows.Forms.Form
    $dialog.Text='Clash 本机访问密钥'
    $dialog.Size=New-Object Drawing.Size(540,220)
    $dialog.StartPosition='CenterParent'
    $dialog.FormBorderStyle='FixedDialog'
    $dialog.MaximizeBox=$false
    $label=New-Object Windows.Forms.Label
    $label.Text='仅保存在本机。请填写已启用的本地 API 密钥；无认证时留空。'
    $label.SetBounds(15,15,495,50)
    $input=New-Object Windows.Forms.TextBox
    $input.UseSystemPasswordChar=$true
    $input.MaxLength=4096
    $input.SetBounds(15,70,495,30)
    $accept=New-Object Windows.Forms.Button
    $accept.Text='确认'
    $accept.DialogResult='OK'
    $accept.SetBounds(310,120,95,35)
    $cancel=New-Object Windows.Forms.Button
    $cancel.Text='取消'
    $cancel.DialogResult='Cancel'
    $cancel.SetBounds(415,120,95,35)
    $dialog.Controls.AddRange(@($label,$input,$accept,$cancel))
    $dialog.AcceptButton=$accept
    $dialog.CancelButton=$cancel
    try {if ($dialog.ShowDialog($script:p6Form) -eq 'OK') {return @{accepted=$true; value=$input.Text}}; return @{accepted=$false; value=$null}}
    finally {$input.Clear(); $dialog.Dispose()}
}
function Run-P6Action([string]$Action) {
    if ($script:p6Busy) {return}
    $profile = ''
    $bundle = ''
    $auto = $false
    $credential = $null
    if ($Action -in @('pause','resume','remove','purge')) {
        $index=$script:p6Profiles.SelectedIndex
        if ($index -lt 0 -or $index -ge $script:p6Entries.Count) {return}
        $profile=$script:p6Entries[$index].id
    }
    if ($Action -in @('install','import')) {
        $bundle=$script:p6Bundle.Text
        if ($Action -eq 'import' -and -not $bundle) {
            [void][Windows.Forms.MessageBox]::Show('请先选择从网页下载的设备配置 ZIP。','客户端管理'); return
        }
        if ($bundle) {
            if ($script:p6Automatic.Checked) {$auto=$true}
            else {
                $manual=Get-P6ManualCredential
                if (-not $manual.accepted) {return}
                $credential=$manual.value
            }
        }
    }
    $description = switch ($Action) {
        'remove' {'移除此设备，将停止它的采集上传并保留本机密钥和队列。此操作不会撤销 VPS 身份。'}
        'purge' {'永久清除此已移除设备的本机密钥和队列，无法撤销。此操作不会删除 VPS 历史。'}
        'uninstall' {'卸载本机客户端服务和程序。已移除设备 的保留数据不会被清除。'}
        'rollback' {'恢复上一套已验证的签名运行程序，保留设备配置、密钥和队列。'}
        default {''}
    }
    $targetLabel = if ($profile) {[string]$script:p6Profiles.Items[$script:p6Profiles.SelectedIndex]} else {''}
    if ($description -and [Windows.Forms.MessageBox]::Show(($description + $(if ($targetLabel) {"`r`n目标设备："+$targetLabel} else {''})),'客户端管理','OKCancel','Warning') -ne 'OK') {return}
    $script:p6Busy=$true
    foreach ($button in $script:p6Buttons.Values) {$button.Enabled=$false}
    $script:p6Autostart.Enabled=$false
    $script:p6Notice.Text='正在执行，请等待安全完成；不会强制结束服务进程。'
    try {
        $result=Invoke-P6Backend $Action $profile $bundle $auto $credential
        if (-not $result.ok -and $result.kind -eq 'discovery') {
            [void][Windows.Forms.MessageBox]::Show('未能安全读取匹配的 Clash Verge 配置。请确认 API 已启用，端口与设备配置一致；也可在下一窗口手动填写本机密钥。程序不会自动修改 Clash。','客户端管理')
            $manual=Get-P6ManualCredential
            if (-not $manual.accepted) {return}
            $result=Invoke-P6Backend $Action $profile $bundle $false $manual.value
            $manual.value=$null
        }
        if (-not $result.ok -and $result.kind -eq 'cleanup') {
            [void][Windows.Forms.MessageBox]::Show('凭据暂存未能清理，操作结果需要回读。请保留安装包并联系管理员；暂存文件仍受本机管理员权限保护。','客户端管理','OK','Warning')
        } elseif (-not $result.ok -and $Action -in @('autostart-on','autostart-off')) {
            [void][Windows.Forms.MessageBox]::Show('开机设置未能确认。请刷新查看实际设置；若仍无法读取，请联系管理员。','客户端管理','OK','Error')
        } elseif (-not $result.ok) {
            [void][Windows.Forms.MessageBox]::Show('操作未完成。请核对设备配置版本、本机 Clash API、显式节点和访问密钥，再重试。已保留可恢复的安装状态；请勿重复创建身份。','客户端管理','OK','Error')
        } else {$script:p6Notice.Text='操作已完成。上传和队列状态可在下面查看。'}
    } finally {
        $credential=$null
        $script:p6Busy=$false
        $script:p6Buttons['install'].Enabled=$true
        $script:p6Buttons['refresh'].Enabled=$true
        Refresh-P6Status
    }
}
function New-P6ManagerForm {
    Add-Type -AssemblyName System.Windows.Forms,System.Drawing -ErrorAction Stop
    [Windows.Forms.Application]::EnableVisualStyles()
    $script:p6Busy=$false
    $script:p6Pending=$false
    $script:p6Entries=@()
    $script:p6Buttons=@{}
    $script:p6Form=New-Object Windows.Forms.Form
    $script:p6Form.Text='客户端管理'
    $script:p6Form.Size=New-Object Drawing.Size(1040,820)
    $script:p6Form.AutoScroll=$true
    $script:p6Form.MinimumSize=New-Object Drawing.Size(780,520)
    $area=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $script:p6Form.Size=New-Object Drawing.Size([Math]::Min(1040,$area.Width-40),[Math]::Min(820,$area.Height-40))
    $script:p6Form.StartPosition='CenterScreen'
    $script:p6Heading=New-Object Windows.Forms.Label
    $script:p6Heading.SetBounds(20,15,980,45)
    $script:p6Heading.Text='读取状态中…'
    $script:p6Autostart=New-Object Windows.Forms.CheckBox
    $script:p6Autostart.Text='开机自动运行'
    $script:p6Autostart.AutoCheck=$false
    $script:p6Autostart.Enabled=$false
    $script:p6Autostart.SetBounds(20,48,145,24)
    $script:p6Autostart.Add_Click({
        if ($script:p6Busy -or $script:p6Pending -or -not $script:p6Autostart.Enabled) {return}
        Run-P6Action $(if ($script:p6Autostart.Checked) {'autostart-off'} else {'autostart-on'})
    })
    $script:p6StartupNote=New-Object Windows.Forms.Label
    $script:p6StartupNote.Text='读取开机设置中…'
    $script:p6StartupNote.SetBounds(170,48,830,24)
    $script:p6Heading.Height=30
    $label=New-Object Windows.Forms.Label
    $label.Text='设备配置（包含密钥，请妥善保管）：'
    $label.SetBounds(20,70,400,25)
    $script:p6Bundle=New-Object Windows.Forms.TextBox
    $script:p6Bundle.ReadOnly=$true
    $script:p6Bundle.SetBounds(20,100,800,30)
    $pick=New-Object Windows.Forms.Button
    $pick.Text='选择配置'
    $pick.SetBounds(835,98,165,35)
    $pick.Add_Click({if ($script:p6Busy) {return}; $dialog=New-Object Windows.Forms.OpenFileDialog; $dialog.Filter='设备配置 ZIP|*.zip'; $dialog.Multiselect=$false; try {if ($dialog.ShowDialog($script:p6Form) -eq 'OK') {$script:p6Bundle.Text=$dialog.FileName}} finally {$dialog.Dispose()}})
    $script:p6Automatic=New-Object Windows.Forms.CheckBox
    $script:p6Automatic.Text='尝试安全读取当前用户的 Clash Verge 配置（地址必须与设备配置一致）'
    $script:p6Automatic.Checked=$true
    $script:p6Automatic.SetBounds(20,140,900,30)
    $script:p6Profiles=New-Object Windows.Forms.ListBox
    $script:p6Profiles.SetBounds(20,240,335,420)
    $script:p6Profiles.Add_SelectedIndexChanged({if (-not $script:p6Busy) {Update-P6Selection}})
    $script:p6Details=New-Object Windows.Forms.Label
    $script:p6Details.SetBounds(370,240,510,50)
    $technical=New-Object Windows.Forms.Button
    $technical.Text='技术详情'
    $technical.SetBounds(885,240,115,35)
    $technical.Add_Click({
        $i=$script:p6Profiles.SelectedIndex
        if ($i -ge 0 -and $i -lt $script:p6Entries.Count) {
            $entry=$script:p6Entries[$i]
            $text='配置内部标识：'+$entry.id
            if ($entry.live) {$text+="`r`nprobe_id："+$entry.value.probe_id+"`r`nserver_id："+$entry.value.server_id}
            [void][Windows.Forms.MessageBox]::Show($text,'技术详情')
        }
    })
    $script:p6Grid=New-Object Windows.Forms.DataGridView
    $script:p6Grid.SetBounds(370,295,630,365)
    $script:p6Grid.ReadOnly=$true
    $script:p6Grid.AllowUserToAddRows=$false
    $script:p6Grid.AllowUserToDeleteRows=$false
    $script:p6Grid.RowHeadersVisible=$false
    $script:p6Grid.AutoSizeColumnsMode='Fill'
    [void]$script:p6Grid.Columns.Add('metric','指标')
    [void]$script:p6Grid.Columns.Add('state','状态 / 数值')
    [void]$script:p6Grid.Columns.Add('detail','说明')
    $script:p6Notice=New-Object Windows.Forms.Label
    $script:p6Notice.SetBounds(20,720,980,45)
    $script:p6Form.Controls.AddRange(@($script:p6Heading,$script:p6Autostart,$script:p6StartupNote,$label,$script:p6Bundle,$pick,$script:p6Automatic,$script:p6Profiles,$script:p6Details,$technical,$script:p6Grid,$script:p6Notice))
    $actions=@(@('install','安装 / 更新'),@('import','导入设备配置'),@('refresh','刷新状态'),@('rollback','回滚'),@('pause','暂停'),@('resume','恢复'),@('remove','移除设备'),@('purge','永久清除'),@('uninstall','卸载服务'))
    for ($i=0; $i -lt $actions.Count; $i++) {
        $button=New-Object Windows.Forms.Button
        $button.Text=$actions[$i][1]
        $button.Tag=$actions[$i][0]
        if ($i -lt 4) {$button.SetBounds((20+$i*245),185,230,38)} else {$button.SetBounds((20+($i-4)*196),675,185,35)}
        $button.Add_Click({param($sender,$event); if ($sender.Tag -eq 'refresh') {Refresh-P6Status} else {Run-P6Action ([string]$sender.Tag)}})
        $script:p6Buttons[$actions[$i][0]]=$button
        $script:p6Form.Controls.Add($button)
    }
    $script:p6Form.Add_FormClosing({param($sender,$event); if ($script:p6Busy) {$event.Cancel=$true}})
    return $script:p6Form
}
function Show-P6Manager([string]$Python,[string]$Entry,[string]$Package,[string]$Common,[string]$OriginalDirectory) {
    $script:p6Python=$Python
    $script:p6Entry=$Entry
    $script:p6Package=$Package
    $script:p6Common=$Common
    $form=New-P6ManagerForm
    $timer=New-Object Windows.Forms.Timer
    $timer.Interval=15000
    $timer.Add_Tick({Refresh-P6Status})
    $form.Add_Shown({
        Refresh-P6Status
        $candidate=Invoke-P6Backend 'adjacent-bundle' '' $OriginalDirectory $false $null
        if ($candidate.ok -and $candidate.value.state -eq 'selected') {
            $script:p6Bundle.Text=$candidate.value.path
            $d=$candidate.value.display
            $script:p6Heading.Text='已识别配置：客户端 ' + $d.client + ' / 设备 ' + $d.device + '。核对后点击“安装 / 更新”。'
        } elseif ($candidate.ok -and $candidate.value.state -eq 'ambiguous') {
            $script:p6Heading.Text='同目录有多个设备配置，请点击“选择配置”明确选择。'
        } elseif (-not $candidate.ok) {
            $script:p6Heading.Text='同目录配置未通过校验，请重新下载客户端包或明确选择有效配置。'
        }
    })
    try {$timer.Start(); [void]$form.ShowDialog()}
    finally {$timer.Stop(); $timer.Dispose(); $form.Dispose()}
}
