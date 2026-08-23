#requires -version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework
$script:MaximumEmlBytes = 50MB
$script:SelectedEmlPath = $null
$script:Latin1Encoding = [System.Text.Encoding]::GetEncoding(28591)
function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { [System.BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha256.Dispose() }
}
function Read-EmlEntity {
    param([string]$Text)
    $separator = [regex]::Match($Text, "\r?\n\r?\n|\r\r")
    $headerText = if ($separator.Success) { $Text.Substring(0, $separator.Index) } else { $Text }
    $bodyText = if ($separator.Success) { $Text.Substring($separator.Index + $separator.Length) } else { '' }
    $headers = New-Object System.Collections.ArrayList
    $malformedCount = 0
    $unfolded = [regex]::Replace($headerText, "(?:\r\n?|\n)[ \t]+", ' ')
    foreach ($line in [regex]::Split($unfolded, "\r\n?|\n")) {
        if ($line -match '^([!-9;-~]+):\s*(.*)$') {
            [void]$headers.Add([pscustomobject]@{ Name = $Matches[1]; Value = $Matches[2] })
        }
        elseif (-not [string]::IsNullOrWhiteSpace($line)) { $malformedCount++ }
    }
    [pscustomobject]@{ Headers = @($headers); BodyText = $bodyText; MalformedCount = $malformedCount }
}
function Get-EmlHeader {
    param([object[]]$Headers, [string]$Name, [switch]$All)
    $values = @($Headers | Where-Object { [string]::Equals($_.Name, $Name, [System.StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { $_.Value })
    if ($All) { return $values }
    if ($values.Count) { return [string]$values[0] }
}
function ConvertFrom-QuotedPrintableBytes {
    param([string]$Text)
    $textWithoutSoftBreaks = $Text -replace "=\r\n|=\n|=\r", ''
    if ($textWithoutSoftBreaks -match '=(?![0-9A-Fa-f]{2})') { throw 'Invalid quoted-printable content.' }
    $decoder = [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        [string][char][Convert]::ToByte($match.Groups[1].Value, 16)
    }
    $decoded = [regex]::Replace($textWithoutSoftBreaks, '=([0-9A-Fa-f]{2})', $decoder)
    return $script:Latin1Encoding.GetBytes($decoded)
}
function ConvertFrom-Rfc2047Header {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    $decodeWord = [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        try {
            $encoding = [System.Text.Encoding]::GetEncoding($match.Groups[1].Value)
            $payload = $match.Groups[3].Value
            [byte[]]$decodedBytes = if ($match.Groups[2].Value -ieq 'B') {
                [Convert]::FromBase64String($payload)
            } else { ConvertFrom-QuotedPrintableBytes -Text $payload.Replace('_', ' ') }
            return $encoding.GetString($decodedBytes)
        }
        catch { return $match.Value }
    }
    $joinedWords = [regex]::Replace($Value, '(?<=\?=)\s+(?==\?)', '')
    return [regex]::Replace($joinedWords, '=\?([^?]+)\?([bBqQ])\?([^?]*)\?=', $decodeWord)
}
function Convert-TransferContent {
    param([string]$BodyText, [string]$TransferEncoding)
    $encodingName = if ($TransferEncoding) { $TransferEncoding.Trim().ToLowerInvariant() } else { '7bit' }
    if ($encodingName -notin @('base64', 'quoted-printable', '7bit', '8bit', 'binary')) {
        return [pscustomobject]@{ Success = $false; Bytes = [byte[]]@(); Status = 'Unsupported transfer encoding' }
    }
    try {
        switch ($encodingName) {
            'base64' { [byte[]]$bytes = [Convert]::FromBase64String(($BodyText -replace '\s', '')) }
            'quoted-printable' { [byte[]]$bytes = ConvertFrom-QuotedPrintableBytes -Text $BodyText }
            default { [byte[]]$bytes = $script:Latin1Encoding.GetBytes($BodyText) }
        }
        return [pscustomobject]@{ Success = $true; Bytes = $bytes; Status = $null }
    }
    catch { return [pscustomobject]@{ Success = $false; Bytes = [byte[]]@(); Status = 'Decode failed' } }
}
function Split-MultipartBody {
    param([string]$BodyText, [string]$Boundary)
    $parts = New-Object System.Collections.ArrayList
    if (-not $Boundary) { return @($parts) }
    $pattern = '(?m)^--' + [regex]::Escape($Boundary) + '(?<close>--)?[ \t]*\r?$'
    $markers = [regex]::Matches($BodyText, $pattern)
    for ($index = 0; $index -lt $markers.Count; $index++) {
        if ($markers[$index].Groups['close'].Success) { break }
        $start = $markers[$index].Index + $markers[$index].Length
        $end = if ($index + 1 -lt $markers.Count) { $markers[$index + 1].Index } else { $BodyText.Length }
        $part = $BodyText.Substring($start, $end - $start).Trim([char[]]"`r`n")
        if ($part) { [void]$parts.Add($part) }
    }
    return @($parts)
}
function Read-MimeEntity {
    param([object]$Entity, [System.Collections.ArrayList]$TextParts,
        [System.Collections.ArrayList]$Attachments, [System.Collections.ArrayList]$Warnings, [int]$Depth = 0)
    if ($Depth -gt 30) { [void]$Warnings.Add('A MIME nesting limit was reached.'); return }
    $headers = @($entity.Headers)
    if ($entity.MalformedCount) { [void]$Warnings.Add('A MIME section contains malformed headers.') }
    $contentTypeValue = Get-EmlHeader -Headers $headers -Name 'Content-Type'
    try { $contentType = [System.Net.Mime.ContentType]::new($(if ($contentTypeValue) { $contentTypeValue } else { 'text/plain; charset=us-ascii' })) }
    catch {
        $contentType = [System.Net.Mime.ContentType]::new('text/plain; charset=us-ascii')
        [void]$Warnings.Add('A MIME content type is malformed.')
    }
    $mediaType = $contentType.MediaType.ToLowerInvariant()
    if ($mediaType.StartsWith('multipart/')) {
        if ([string]::IsNullOrWhiteSpace($contentType.Boundary)) { [void]$Warnings.Add('A multipart section has no usable boundary.'); return }
        $childParts = @(Split-MultipartBody -BodyText $entity.BodyText -Boundary $contentType.Boundary)
        if (-not $childParts.Count) { [void]$Warnings.Add('A multipart section could not be separated.'); return }
        foreach ($childPart in $childParts) {
            try { Read-MimeEntity -Entity (Read-EmlEntity -Text $childPart) -TextParts $TextParts -Attachments $Attachments -Warnings $Warnings -Depth ($Depth + 1) }
            catch { [void]$Warnings.Add('A MIME section could not be parsed.') }
        }
        return
    }
    $dispositionValue = Get-EmlHeader -Headers $headers -Name 'Content-Disposition'
    $disposition = if ($dispositionValue) { try { [System.Net.Mime.ContentDisposition]::new($dispositionValue) } catch { $null } }
    $filename = if ($disposition) { $disposition.FileName } else { $null }
    if (-not $filename -and $disposition) { $filename = $disposition.Parameters['filename*'] }
    if (-not $filename) { $filename = $contentType.Name }
    if (-not $filename) { $filename = $contentType.Parameters['name*'] }
    if ($filename -match "^[^']*'[^']*'(.*)$") { $filename = $Matches[1] }
    try { $filename = [System.Uri]::UnescapeDataString($filename) } catch {}
    $isAttachment = ($disposition -and $disposition.DispositionType -ieq 'attachment') -or $filename
    if (-not $isAttachment -and $mediaType -notin @('text/plain', 'text/html')) { return }
    $decodedContent = Convert-TransferContent -BodyText $entity.BodyText -TransferEncoding (Get-EmlHeader -Headers $headers -Name 'Content-Transfer-Encoding')
    if ($isAttachment) {
        $displayFilename = if ($filename) { ConvertFrom-Rfc2047Header -Value $filename } else { 'Unnamed attachment' }
        $attachmentSize = $decodedContent.Status
        $attachmentHash = $decodedContent.Status
        $canCopyHash = $false
        if (-not $decodedContent.Success) { [void]$Warnings.Add('An attachment could not be decoded.') }
        else {
            $attachmentSize = '{0:N0} bytes' -f $decodedContent.Bytes.Length
            try {
                $attachmentHash = Get-Sha256Hex -Bytes ([byte[]]$decodedContent.Bytes)
                $canCopyHash = $true
            }
            catch {
                $attachmentHash = 'Hash failed'
                [void]$Warnings.Add('An attachment hash could not be calculated.')
            }
        }
        [void]$Attachments.Add([pscustomobject]@{
            Filename = $displayFilename; ContentType = $mediaType; Size = $attachmentSize
            Hash = $attachmentHash; CanCopyHash = $canCopyHash
        })
        return
    }
    if ($mediaType -in @('text/plain', 'text/html')) {
        if (-not $decodedContent.Success) { [void]$Warnings.Add('A text MIME section could not be decoded.'); return }
        $charset = if ($contentType.CharSet) { $contentType.CharSet } else { 'utf-8' }
        try {
            $textEncoding = [System.Text.Encoding]::GetEncoding($charset)
            $decodedText = $textEncoding.GetString([byte[]]$decodedContent.Bytes)
            [void]$TextParts.Add([pscustomobject]@{ MediaType = $mediaType; Text = $decodedText })
        }
        catch { [void]$Warnings.Add('A text MIME charset is unsupported.') }
    }
}
function Get-ExtractedUrls {
    param([object[]]$TextParts)
    $urls = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $urlPattern = '(?i)\bhttps?://[^\s<>"'']+'
    $trailingCharacters = [char[]]@('.', ',', ';', ':', '!', '?', ')', ']', '}')
    foreach ($part in $TextParts) {
        foreach ($match in [System.Text.RegularExpressions.Regex]::Matches([string]$part.Text, $urlPattern)) {
            $url = $match.Value.TrimEnd($trailingCharacters)
            if ((-not [string]::IsNullOrWhiteSpace($url)) -and $seen.Add($url)) {
                [void]$urls.Add($url)
            }
        }
    }
    return @($urls)
}
function Get-DomainFromAddressHeader {
    param([string]$AddressHeader)
    $match = [System.Text.RegularExpressions.Regex]::Match(
        [string]$AddressHeader,
        "(?i)[A-Z0-9.!#$%&'*+/=?^_``{|}~-]+@(?<domain>[A-Z0-9.-]+)"
    )
    if ($match.Success) { return $match.Groups['domain'].Value }
    return 'Not present'
}
function Get-NormalizedAuthenticationResult {
    param(
        [object[]]$Headers,
        [string]$Method
    )
    $knownResults = 'pass|fail|softfail|neutral|none|temperror|permerror'
    foreach ($value in @(Get-EmlHeader -Headers $Headers -Name 'Authentication-Results' -All)) {
        $pattern = '(?i)(?:^|[;\s])' + [System.Text.RegularExpressions.Regex]::Escape($Method) + '\s*=\s*(?<result>' + $knownResults + ')\b'
        $match = [System.Text.RegularExpressions.Regex]::Match($value, $pattern)
        if ($match.Success) {
            return $match.Groups['result'].Value.ToUpperInvariant()
        }
    }
    if ($Method -eq 'spf') {
        foreach ($value in @(Get-EmlHeader -Headers $Headers -Name 'Received-SPF' -All)) {
            $match = [System.Text.RegularExpressions.Regex]::Match($value, '(?i)^\s*(?<result>pass|fail|softfail|neutral|none|temperror|permerror)\b')
            if ($match.Success) {
                return $match.Groups['result'].Value.ToUpperInvariant()
            }
        }
    }
    return 'Not present'
}
function Get-FirstReceivedEvidence {
    param([object[]]$Headers)
    $receivedValues = @(Get-EmlHeader -Headers $Headers -Name 'Received' -All)
    if (-not $receivedValues.Count) {
        return [pscustomobject]@{ Host = 'Not present'; IP = 'Not present' }
    }
    $oldestReceived = [string]$receivedValues[$receivedValues.Count - 1]
    $fromMatch = [System.Text.RegularExpressions.Regex]::Match(
        $oldestReceived,
        '(?is)(?:^|\s)from\s+(?<segment>.+?)(?=\s+by\s+|\s+via\s+|\s+with\s+|\s*;|$)'
    )
    if (-not $fromMatch.Success) {
        return [pscustomobject]@{ Host = 'Not present'; IP = 'Not present' }
    }
    $segment = $fromMatch.Groups['segment'].Value.Trim()
    $hostMatch = [System.Text.RegularExpressions.Regex]::Match($segment, '^(?<host>[^\s(;]+)')
    $hostValue = if ($hostMatch.Success) { $hostMatch.Groups['host'].Value } else { 'Not present' }
    $ipValue = 'Not present'
    $ipMatch = [System.Text.RegularExpressions.Regex]::Match(
        $segment,
        '(?i)\[(?:IPv6:)?(?<ip>[0-9A-F:.]+)\]|(?<![\d.])(?<ip>(?:\d{1,3}\.){3}\d{1,3})(?![\d.])'
    )
    if ($ipMatch.Success) {
        $parsedIp = $null
        if ([System.Net.IPAddress]::TryParse($ipMatch.Groups['ip'].Value, [ref]$parsedIp)) {
            $ipValue = $parsedIp.ToString()
        }
    }
    return [pscustomobject]@{ Host = $hostValue; IP = $ipValue }
}
function Get-DisplayHeaderValue {
    param([object[]]$Headers, [string]$Name)
    $value = Get-EmlHeader -Headers $Headers -Name $Name
    if ([string]::IsNullOrWhiteSpace($value)) { return 'Not present' }
    ConvertFrom-Rfc2047Header -Value $value
}
function Test-EmlFile {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Valid = $false; Message = 'Choose an EML file first.' }
    }
    if (-not [System.IO.File]::Exists($Path)) {
        return [pscustomobject]@{ Valid = $false; Message = 'The selected file no longer exists.' }
    }
    if (-not [string]::Equals([System.IO.Path]::GetExtension($Path), '.eml', [System.StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{ Valid = $false; Message = 'Select a file with the .eml extension.' }
    }
    try {
        $fileInfo = New-Object System.IO.FileInfo($Path)
        if ($fileInfo.Length -eq 0) {
            return [pscustomobject]@{ Valid = $false; Message = 'The selected EML file is empty.' }
        }
        if ($fileInfo.Length -gt $script:MaximumEmlBytes) {
            return [pscustomobject]@{ Valid = $false; Message = 'The selected EML file is larger than 50 MB.' }
        }
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Message = 'The selected file cannot be inspected.' }
    }
    return [pscustomobject]@{ Valid = $true; Message = $null }
}
function Invoke-PhishFryAnalysis {
    param([string]$Path)
    $validation = Test-EmlFile -Path $Path
    if (-not $validation.Valid) {
        throw $validation.Message
    }
    try {
        [byte[]]$fileBytes = [System.IO.File]::ReadAllBytes($Path)
        $rawText = $script:Latin1Encoding.GetString($fileBytes)
        $rootEntity = Read-EmlEntity -Text $rawText
        $headers = @($rootEntity.Headers)
    }
    catch {
        throw 'The selected EML file could not be read or parsed.'
    }
    if ($headers.Count -eq 0) {
        throw 'The EML file does not contain usable message headers.'
    }
    $warnings = New-Object System.Collections.ArrayList
    $firstSeen = Get-FirstReceivedEvidence -Headers $headers
    $fromValue = Get-DisplayHeaderValue -Headers $headers -Name 'From'
    $fromDomain = Get-DomainFromAddressHeader -AddressHeader $fromValue
    $senderValue = Get-DisplayHeaderValue -Headers $headers -Name 'Sender'
    $senderDomain = if ($senderValue -eq 'Not present') {
        $fromDomain
    }
    else {
        Get-DomainFromAddressHeader -AddressHeader $senderValue
    }
    $envelopeSender = Get-DisplayHeaderValue -Headers $headers -Name 'Return-Path'
    $envelopeDomain = Get-DomainFromAddressHeader -AddressHeader $envelopeSender
    $textParts = New-Object System.Collections.ArrayList
    $attachments = New-Object System.Collections.ArrayList
    try {
        Read-MimeEntity -Entity $rootEntity -TextParts $textParts -Attachments $attachments -Warnings $warnings
    }
    catch {
        [void]$warnings.Add('The MIME structure could not be fully parsed.')
    }
    $urls = @(Get-ExtractedUrls -TextParts @($textParts))
    return [pscustomobject]@{
        Overview = [ordered]@{
            'Subject' = Get-DisplayHeaderValue -Headers $headers -Name 'Subject'
            'Date'    = Get-DisplayHeaderValue -Headers $headers -Name 'Date'
            'From'    = $fromValue
            'To'      = Get-DisplayHeaderValue -Headers $headers -Name 'To'
            'Cc'      = Get-DisplayHeaderValue -Headers $headers -Name 'Cc'
        }
        Authentication = [ordered]@{
            'SPF'   = Get-NormalizedAuthenticationResult -Headers $headers -Method 'spf'
            'DKIM'  = Get-NormalizedAuthenticationResult -Headers $headers -Method 'dkim'
            'DMARC' = Get-NormalizedAuthenticationResult -Headers $headers -Method 'dmarc'
        }
        Metadata = [ordered]@{
            'From Domain'     = $fromDomain
            'Sender Domain'   = $senderDomain
            'Envelope Sender' = $envelopeSender
            'Envelope Domain' = $envelopeDomain
            'Reply-To'        = Get-DisplayHeaderValue -Headers $headers -Name 'Reply-To'
            'First Seen IP'   = $firstSeen.IP
            'First Seen Host' = $firstSeen.Host
        }
        Urls        = $urls
        Attachments = @($attachments)
        Warnings    = @($warnings)
    }
}
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:shell="clr-namespace:System.Windows.Shell;assembly=PresentationFramework" Title="PhishFry - EML Analyzer" Width="1280" Height="912" MinWidth="1000" MinHeight="680" WindowStartupLocation="CenterScreen" WindowStyle="None" ResizeMode="CanResize" Background="#F3F6F4" FontFamily="Segoe UI" Foreground="#172729">
<shell:WindowChrome.WindowChrome>
<shell:WindowChrome CaptionHeight="46" ResizeBorderThickness="6" CornerRadius="0" GlassFrameThickness="0" />
</shell:WindowChrome.WindowChrome>
<Window.Resources>
<BooleanToVisibilityConverter x:Key="BooleanToVisibility" />
<Style x:Key="ActionButton" TargetType="Button"><Setter Property="Height" Value="40" /><Setter Property="MinWidth" Value="110" /><Setter Property="Padding" Value="16,0" /><Setter Property="Background" Value="White" /><Setter Property="BorderBrush" Value="#AEBAB6" /><Setter Property="BorderThickness" Value="1" /><Setter Property="FontFamily" Value="Segoe UI Semibold" /><Setter Property="FontSize" Value="14" /><Setter Property="Cursor" Value="Hand" />
</Style>
<Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource ActionButton}"><Setter Property="Background" Value="#D96D00" /><Setter Property="Foreground" Value="White" /><Setter Property="BorderBrush" Value="#D96D00" />
</Style>
<Style x:Key="TitleBarButton" TargetType="Button"><Setter Property="Background" Value="Transparent" /><Setter Property="BorderThickness" Value="0" /><Setter Property="Cursor" Value="Hand" /><Setter Property="Focusable" Value="False" /><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border Background="{TemplateBinding Background}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" /></Border></ControlTemplate></Setter.Value></Setter><Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#313131" /></Trigger><Trigger Property="IsPressed" Value="True"><Setter Property="Background" Value="#282828" /></Trigger></Style.Triggers>
</Style>
<Style x:Key="CloseTitleBarButton" TargetType="Button" BasedOn="{StaticResource TitleBarButton}"><Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#C42B1C" /></Trigger><Trigger Property="IsPressed" Value="True"><Setter Property="Background" Value="#A92318" /></Trigger></Style.Triggers>
</Style>
<Style x:Key="CopyButton" TargetType="Button"><Setter Property="ToolTip" Value="Copy value" /><Setter Property="Width" Value="32" /><Setter Property="Height" Value="28" /><Setter Property="Padding" Value="0" /><Setter Property="Margin" Value="4,0" /><Setter Property="Background" Value="Transparent" /><Setter Property="BorderThickness" Value="0" /><Setter Property="Cursor" Value="Hand" /><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="CopySurface" Background="Transparent" CornerRadius="3"><Grid Width="16" Height="16"><Rectangle Width="9" Height="10" HorizontalAlignment="Right" VerticalAlignment="Top" Stroke="#52615E" StrokeThickness="1.2" RadiusX="1" RadiusY="1" /><Rectangle Width="9" Height="10" HorizontalAlignment="Left" VerticalAlignment="Bottom" Fill="White" Stroke="#52615E" StrokeThickness="1.2" RadiusX="1" RadiusY="1" /></Grid></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="CopySurface" Property="Background" Value="#E8EEEB" /></Trigger><Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0" /></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
</Style>
<Style x:Key="Section" TargetType="Border"><Setter Property="Background" Value="White" /><Setter Property="BorderBrush" Value="#D5DEDA" /><Setter Property="BorderThickness" Value="1" /><Setter Property="CornerRadius" Value="3" />
</Style>
<Style x:Key="SectionTitle" TargetType="TextBlock"><Setter Property="Foreground" Value="White" /><Setter Property="FontFamily" Value="Segoe UI Semibold" /><Setter Property="FontSize" Value="15" /><Setter Property="Margin" Value="12,0" /><Setter Property="VerticalAlignment" Value="Center" />
</Style>
<DataTemplate x:Key="ValueRowTemplate"><Border BorderBrush="#E2E8E5" BorderThickness="0,0,0,1" MinHeight="34"><Grid Margin="12,0,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="165" /><ColumnDefinition Width="*" /><ColumnDefinition Width="52" /></Grid.ColumnDefinitions><TextBlock Text="{Binding Label}" FontFamily="Segoe UI Semibold" FontSize="13" VerticalAlignment="Center" /><TextBlock Grid.Column="1" Text="{Binding Value}" FontFamily="Consolas" FontSize="12" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" ToolTip="{Binding Value}" /><Button Grid.Column="2" Style="{StaticResource CopyButton}" Tag="{Binding Value}" IsEnabled="{Binding CanCopy}" Visibility="{Binding CanCopy, Converter={StaticResource BooleanToVisibility}}" /></Grid></Border>
</DataTemplate>
<DataTemplate x:Key="UrlTemplate"><Border BorderBrush="#E2E8E5" BorderThickness="0,0,0,1" MinHeight="36"><Grid Margin="12,0,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*" /><ColumnDefinition Width="52" /></Grid.ColumnDefinitions><TextBlock Text="{Binding Value}" FontFamily="Consolas" FontSize="12" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" ToolTip="{Binding Value}" /><Button Grid.Column="1" Style="{StaticResource CopyButton}" Tag="{Binding Value}" /></Grid></Border>
</DataTemplate>
</Window.Resources>
<Grid>
<Grid.RowDefinitions><RowDefinition Height="46" /><RowDefinition Height="70" /><RowDefinition Height="*" /><RowDefinition Height="30" />
</Grid.RowDefinitions>
<Border Grid.Row="0" Background="#062A2D"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*" /><ColumnDefinition Width="48" /><ColumnDefinition Width="48" /><ColumnDefinition Width="48" /></Grid.ColumnDefinitions><StackPanel Grid.ColumnSpan="4" Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center" IsHitTestVisible="False"><TextBlock Text="PHISHFRY" Foreground="#D96D00" FontFamily="Segoe UI Semibold" FontSize="24" VerticalAlignment="Center" /><TextBlock Text="-" Foreground="White" FontFamily="Segoe UI" FontSize="17" Margin="10,0" VerticalAlignment="Center" /><TextBlock Text="EML Evidence Analyzer" Foreground="White" FontFamily="Segoe UI" FontSize="17" Margin="0,2,0,0" VerticalAlignment="Center" /></StackPanel><Button x:Name="MinimizeButton" Grid.Column="1" ToolTip="Minimize" Style="{StaticResource TitleBarButton}" shell:WindowChrome.IsHitTestVisibleInChrome="True"><Viewbox Width="12" Height="12"><Canvas Width="12" Height="12"><Path Data="M1,6 L11,6" Stroke="White" StrokeThickness="1" StrokeStartLineCap="Square" StrokeEndLineCap="Square" /></Canvas></Viewbox></Button><Button x:Name="MaximizeButton" Grid.Column="2" ToolTip="Maximize or restore" Style="{StaticResource TitleBarButton}" shell:WindowChrome.IsHitTestVisibleInChrome="True"><Grid><Viewbox x:Name="MaximizeGlyph" Width="12" Height="12"><Canvas Width="12" Height="12"><Rectangle Canvas.Left="1.5" Canvas.Top="1.5" Width="9" Height="9" Stroke="White" StrokeThickness="1" /></Canvas></Viewbox><Viewbox x:Name="RestoreGlyph" Width="12" Height="12" Visibility="Collapsed"><Canvas Width="12" Height="12"><Path Data="M4,3 L4,1.5 L10.5,1.5 L10.5,8 L9,8" Stroke="White" StrokeThickness="1" /><Rectangle Canvas.Left="1.5" Canvas.Top="3.5" Width="7" Height="7" Stroke="White" StrokeThickness="1" /></Canvas></Viewbox></Grid></Button><Button x:Name="CloseButton" Grid.Column="3" ToolTip="Close" Style="{StaticResource CloseTitleBarButton}" shell:WindowChrome.IsHitTestVisibleInChrome="True"><Viewbox Width="12" Height="12"><Canvas Width="12" Height="12"><Path Data="M2,2 L10,10 M10,2 L2,10" Stroke="White" StrokeThickness="1" StrokeStartLineCap="Square" StrokeEndLineCap="Square" /></Canvas></Viewbox></Button></Grid>
</Border>
<Grid Grid.Row="1" Margin="22,12,22,10"><Grid.ColumnDefinitions><ColumnDefinition Width="85" /><ColumnDefinition Width="*" /><ColumnDefinition Width="12" /><ColumnDefinition Width="125" /><ColumnDefinition Width="12" /><ColumnDefinition Width="125" /><ColumnDefinition Width="12" /><ColumnDefinition Width="110" /></Grid.ColumnDefinitions><TextBlock Text="Email file" FontFamily="Segoe UI Semibold" VerticalAlignment="Center" /><TextBox x:Name="FilePathBox" Grid.Column="1" Height="40" IsReadOnly="True" Padding="10,0" VerticalContentAlignment="Center" Background="White" BorderBrush="#D5DEDA" /><Button x:Name="ChooseButton" Grid.Column="3" Content="Choose EML" Style="{StaticResource ActionButton}" /><Button x:Name="AnalyzeButton" Grid.Column="5" Content="Analyze" Style="{StaticResource PrimaryButton}" IsEnabled="False" /><Button x:Name="ClearButton" Grid.Column="7" Content="Clear" Style="{StaticResource ActionButton}" />
</Grid>
<ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto"><Grid Margin="22,8,22,6"><Grid.RowDefinitions><RowDefinition Height="Auto" /><RowDefinition Height="12" /><RowDefinition Height="Auto" /><RowDefinition Height="12" /><RowDefinition Height="Auto" /></Grid.RowDefinitions><Grid Grid.Row="0"><Grid.ColumnDefinitions><ColumnDefinition Width="49*" /><ColumnDefinition Width="12" /><ColumnDefinition Width="51*" /></Grid.ColumnDefinitions>
<StackPanel Grid.Column="0">
<Border Style="{StaticResource Section}" Margin="0,0,0,12"><Grid><Grid.RowDefinitions><RowDefinition Height="36" /><RowDefinition Height="Auto" /></Grid.RowDefinitions><Border Background="#062A2D" CornerRadius="5,5,0,0"><TextBlock Text="Overview" Style="{StaticResource SectionTitle}" /></Border><ItemsControl x:Name="OverviewList" Grid.Row="1" ItemTemplate="{StaticResource ValueRowTemplate}" /></Grid></Border>
<Border Style="{StaticResource Section}" Margin="0,0,0,12"><Grid><Grid.RowDefinitions><RowDefinition Height="36" /><RowDefinition Height="58" /></Grid.RowDefinitions><Border Background="#062A2D" CornerRadius="5,5,0,0"><TextBlock Text="Reported Authentication" Style="{StaticResource SectionTitle}" /></Border><Grid Grid.Row="1" Margin="8"><Grid.ColumnDefinitions><ColumnDefinition Width="*" /><ColumnDefinition Width="8" /><ColumnDefinition Width="*" /><ColumnDefinition Width="8" /><ColumnDefinition Width="*" /></Grid.ColumnDefinitions><Border Grid.Column="0" BorderBrush="#D5DEDA" BorderThickness="1" CornerRadius="4"><StackPanel Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center"><TextBlock Text="SPF" FontFamily="Segoe UI Semibold" Margin="0,0,10,0" /><TextBlock x:Name="SpfStatus" Text="Not present" Foreground="#778481" /></StackPanel></Border><Border Grid.Column="2" BorderBrush="#D5DEDA" BorderThickness="1" CornerRadius="4"><StackPanel Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center"><TextBlock Text="DKIM" FontFamily="Segoe UI Semibold" Margin="0,0,10,0" /><TextBlock x:Name="DkimStatus" Text="Not present" Foreground="#778481" /></StackPanel></Border><Border Grid.Column="4" BorderBrush="#D5DEDA" BorderThickness="1" CornerRadius="4"><StackPanel Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center"><TextBlock Text="DMARC" FontFamily="Segoe UI Semibold" Margin="0,0,10,0" /><TextBlock x:Name="DmarcStatus" Text="Not present" Foreground="#778481" /></StackPanel></Border></Grid></Grid></Border></StackPanel>
<Border Grid.Column="2" Style="{StaticResource Section}"><Grid><Grid.RowDefinitions><RowDefinition Height="36" /><RowDefinition Height="Auto" /></Grid.RowDefinitions><Border Background="#062A2D" CornerRadius="5,5,0,0"><TextBlock Text="Sender Evidence" Style="{StaticResource SectionTitle}" /></Border><ItemsControl x:Name="MetadataList" Grid.Row="1" ItemTemplate="{StaticResource ValueRowTemplate}" /></Grid></Border></Grid>
<Border Grid.Row="2" Style="{StaticResource Section}"><Grid><Grid.RowDefinitions><RowDefinition Height="36" /><RowDefinition Height="Auto" /></Grid.RowDefinitions><Border Background="#062A2D" CornerRadius="5,5,0,0"><TextBlock Text="URLs" Style="{StaticResource SectionTitle}" /></Border><Grid Grid.Row="1"><ItemsControl x:Name="UrlList" ItemTemplate="{StaticResource UrlTemplate}" /><TextBlock x:Name="UrlEmpty" Text="Not present" Margin="12" Foreground="#778481" /></Grid></Grid></Border>
<Border Grid.Row="4" Style="{StaticResource Section}"><Grid><Grid.RowDefinitions><RowDefinition Height="36" /><RowDefinition Height="Auto" /></Grid.RowDefinitions><Border Background="#062A2D" CornerRadius="5,5,0,0"><TextBlock Text="Attachments" Style="{StaticResource SectionTitle}" /></Border><Grid Grid.Row="1"><Grid.RowDefinitions><RowDefinition Height="34" /><RowDefinition Height="Auto" /></Grid.RowDefinitions><Grid Background="#F7F9F8"><Grid.ColumnDefinitions><ColumnDefinition Width="240" /><ColumnDefinition Width="220" /><ColumnDefinition Width="130" /><ColumnDefinition Width="*" /></Grid.ColumnDefinitions><TextBlock Text="Filename" Margin="12,0" FontFamily="Segoe UI Semibold" VerticalAlignment="Center" /><TextBlock Grid.Column="1" Text="Content Type" Margin="12,0" FontFamily="Segoe UI Semibold" VerticalAlignment="Center" /><TextBlock Grid.Column="2" Text="Decoded Size" Margin="12,0" FontFamily="Segoe UI Semibold" VerticalAlignment="Center" /><TextBlock Grid.Column="3" Text="SHA-256" Margin="12,0" FontFamily="Segoe UI Semibold" VerticalAlignment="Center" /></Grid>
<ItemsControl x:Name="AttachmentGrid" Grid.Row="1"><ItemsControl.ItemTemplate><DataTemplate><Border BorderBrush="#E2E8E5" BorderThickness="0,1,0,0" MinHeight="34"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="240" /><ColumnDefinition Width="220" /><ColumnDefinition Width="130" /><ColumnDefinition Width="*" /></Grid.ColumnDefinitions><TextBlock Text="{Binding Filename}" Margin="12,0" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" /><TextBlock Grid.Column="1" Text="{Binding ContentType}" Margin="12,0" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" /><TextBlock Grid.Column="2" Text="{Binding Size}" Margin="12,0" VerticalAlignment="Center" /><Grid Grid.Column="3"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="40"/></Grid.ColumnDefinitions><TextBlock Text="{Binding Hash}" Margin="12,0" FontFamily="Consolas" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" ToolTip="{Binding Hash}" /><Button Grid.Column="1" Style="{StaticResource CopyButton}" Tag="{Binding Hash}" IsEnabled="{Binding CanCopyHash}" /></Grid></Grid></Border></DataTemplate></ItemsControl.ItemTemplate></ItemsControl><TextBlock x:Name="AttachmentEmpty" Text="Not present" Margin="12" Foreground="#778481" /></Grid></Grid></Border></Grid>
</ScrollViewer>
<Border Grid.Row="3" Background="#E8EEEB" BorderBrush="#D5DEDA" BorderThickness="0,1,0,0"><TextBlock x:Name="StatusText" Margin="22,0" VerticalAlignment="Center" FontSize="12" Foreground="#778481" />
</Border>
</Grid>
</Window>
'@
try {
    $window = [System.Windows.Markup.XamlReader]::Parse($xaml)
}
catch {
    [System.Windows.MessageBox]::Show('PhishFry could not open its interface.', 'PhishFry') | Out-Null
    return
}
$FilePathBox = $window.FindName('FilePathBox')
$ChooseButton = $window.FindName('ChooseButton')
$AnalyzeButton = $window.FindName('AnalyzeButton')
$ClearButton = $window.FindName('ClearButton')
$MinimizeButton = $window.FindName('MinimizeButton')
$MaximizeButton = $window.FindName('MaximizeButton')
$MaximizeGlyph = $window.FindName('MaximizeGlyph')
$RestoreGlyph = $window.FindName('RestoreGlyph')
$CloseButton = $window.FindName('CloseButton')
$OverviewList = $window.FindName('OverviewList')
$MetadataList = $window.FindName('MetadataList')
$UrlList = $window.FindName('UrlList')
$AttachmentGrid = $window.FindName('AttachmentGrid')
$UrlEmpty = $window.FindName('UrlEmpty')
$AttachmentEmpty = $window.FindName('AttachmentEmpty')
$SpfStatus = $window.FindName('SpfStatus')
$DkimStatus = $window.FindName('DkimStatus')
$DmarcStatus = $window.FindName('DmarcStatus')
$StatusText = $window.FindName('StatusText')
$MinimizeButton.Add_Click({ $window.WindowState = [System.Windows.WindowState]::Minimized })
$MaximizeButton.Add_Click({
    if ($window.WindowState -eq [System.Windows.WindowState]::Maximized) {
        $window.WindowState = [System.Windows.WindowState]::Normal
    }
    else {
        $window.WindowState = [System.Windows.WindowState]::Maximized
    }
})
$window.Add_StateChanged({
    $isMaximized = $window.WindowState -eq [System.Windows.WindowState]::Maximized
    $MaximizeGlyph.Visibility = if ($isMaximized) { 'Collapsed' } else { 'Visible' }
    $RestoreGlyph.Visibility = if ($isMaximized) { 'Visible' } else { 'Collapsed' }
})
$CloseButton.Add_Click({ $window.Close() })
function Set-Status {
    param([string]$Text, [string]$Color = '#778481')
    $StatusText.Text = $Text
    $StatusText.Foreground = New-Object System.Windows.Media.SolidColorBrush (
        [System.Windows.Media.ColorConverter]::ConvertFromString($Color)
    )
}
function Set-AuthStatus {
    param([System.Windows.Controls.TextBlock]$Control, [string]$Value)
    $Control.Text = $Value
    $color = switch ($Value) {
        'PASS' { '#367A5A' }
        'FAIL' { '#BE4D4D' }
        'Not present' { '#778481' }
        'NONE' { '#778481' }
        default { '#C98236' }
    }
    $Control.Foreground = New-Object System.Windows.Media.SolidColorBrush (
        [System.Windows.Media.ColorConverter]::ConvertFromString($color)
    )
}
function ConvertTo-ValueRows {
    param(
        [System.Collections.IDictionary]$Values,
        [bool]$AllowCopy,
        [bool]$HideMissing = $false
    )
    $rows = New-Object System.Collections.ArrayList
    foreach ($entry in $Values.GetEnumerator()) {
        $value = [string]$entry.Value
        if ($HideMissing -and $value -eq 'Not present') { continue }
        [void]$rows.Add([pscustomobject]@{
            Label   = [string]$entry.Key
            Value   = $value
            CanCopy = $AllowCopy -and $value -notin @('Not present', 'Decode failed', 'Hash failed')
        })
    }
    return @($rows)
}
function Copy-Value {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -in @('Not present', 'Decode failed', 'Hash failed')) {
        return
    }
    try {
        [System.Windows.Clipboard]::SetText($Value)
        Set-Status -Text 'Copied to clipboard.' -Color '#367A5A'
    }
    catch {
        Set-Status -Text 'The value could not be copied.' -Color '#BE4D4D'
    }
}
function Clear-Results {
    $emptyOverview = [ordered]@{
        Subject = 'Not present'; Date = 'Not present'; From = 'Not present'
        To = 'Not present'; Cc = 'Not present'
    }
    $emptyMetadata = [ordered]@{
        'From Domain' = 'Not present'; 'Sender Domain' = 'Not present'
        'Envelope Sender' = 'Not present'; 'Envelope Domain' = 'Not present'
        'Reply-To' = 'Not present'; 'First Seen IP' = 'Not present'
        'First Seen Host' = 'Not present'
    }
    $OverviewList.ItemsSource = @(ConvertTo-ValueRows -Values $emptyOverview -AllowCopy $false)
    $MetadataList.ItemsSource = @(ConvertTo-ValueRows -Values $emptyMetadata -AllowCopy $true)
    $UrlList.ItemsSource = $null
    $AttachmentGrid.ItemsSource = $null
    $UrlEmpty.Visibility = [System.Windows.Visibility]::Visible
    $AttachmentEmpty.Visibility = [System.Windows.Visibility]::Visible
    Set-AuthStatus -Control $SpfStatus -Value 'Not present'
    Set-AuthStatus -Control $DkimStatus -Value 'Not present'
    Set-AuthStatus -Control $DmarcStatus -Value 'Not present'
}
function Show-Analysis {
    param([object]$Analysis)
    $OverviewList.ItemsSource = @(ConvertTo-ValueRows -Values $Analysis.Overview -AllowCopy $false -HideMissing $true)
    $MetadataList.ItemsSource = @(ConvertTo-ValueRows -Values $Analysis.Metadata -AllowCopy $true -HideMissing $true)
    Set-AuthStatus -Control $SpfStatus -Value $Analysis.Authentication['SPF']
    Set-AuthStatus -Control $DkimStatus -Value $Analysis.Authentication['DKIM']
    Set-AuthStatus -Control $DmarcStatus -Value $Analysis.Authentication['DMARC']
    $urlRows = @($Analysis.Urls | ForEach-Object { [pscustomobject]@{ Value = [string]$_ } })
    $UrlList.ItemsSource = $urlRows
    $UrlEmpty.Visibility = if ($urlRows.Count) { 'Collapsed' } else { 'Visible' }
    $AttachmentGrid.ItemsSource = @($Analysis.Attachments)
    $AttachmentEmpty.Visibility = if ($Analysis.Attachments.Count) { 'Collapsed' } else { 'Visible' }
}
$copyHandler = [System.Windows.RoutedEventHandler]{
    param($eventSource, $routedEventArgs)
    [void]$eventSource
    $button = $routedEventArgs.Source
    if (($button -is [System.Windows.Controls.Button]) -and ($button.ToolTip -eq 'Copy value')) {
        Copy-Value -Value ([string]$button.Tag)
        $routedEventArgs.Handled = $true
    }
}
$window.AddHandler([System.Windows.Controls.Button]::ClickEvent, $copyHandler)
$ChooseButton.Add_Click({
    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Title = 'Choose an EML file'
    $dialog.Filter = 'Email message (*.eml)|*.eml'
    $dialog.Multiselect = $false
    $dialog.CheckFileExists = $true
    try { $selected = $dialog.ShowDialog($window) }
    catch {
        Set-Status -Text 'The file picker could not be opened.' -Color '#BE4D4D'
        return
    }
    if ($selected -ne $true) { return }
    $validation = Test-EmlFile -Path $dialog.FileName
    if (-not $validation.Valid) {
        Set-Status -Text $validation.Message -Color '#BE4D4D'
        return
    }
    $script:SelectedEmlPath = $dialog.FileName
    $FilePathBox.Text = $dialog.FileName
    $AnalyzeButton.IsEnabled = $true
    Clear-Results
    Set-Status -Text 'File selected. Click Analyze.'
})
$AnalyzeButton.Add_Click({
    $validation = Test-EmlFile -Path $script:SelectedEmlPath
    if (-not $validation.Valid) {
        $AnalyzeButton.IsEnabled = $false
        Set-Status -Text $validation.Message -Color '#BE4D4D'
        return
    }
    $AnalyzeButton.IsEnabled = $false
    $ChooseButton.IsEnabled = $false
    $ClearButton.IsEnabled = $false
    [System.Windows.Input.Mouse]::OverrideCursor = [System.Windows.Input.Cursors]::Wait
    Clear-Results
    Set-Status -Text 'Analyzing locally…'
    try {
        $analysis = Invoke-PhishFryAnalysis -Path $script:SelectedEmlPath
        Show-Analysis -Analysis $analysis
        if ($analysis.Warnings.Count) {
            Set-Status -Text ('Complete with {0} recoverable MIME warning(s).' -f $analysis.Warnings.Count) -Color '#C98236'
        }
        else {
            Set-Status -Text 'Analysis complete.' -Color '#367A5A'
        }
    }
    catch {
        Clear-Results
        Set-Status -Text 'The EML file could not be analyzed.' -Color '#BE4D4D'
    }
    finally {
        [System.Windows.Input.Mouse]::OverrideCursor = $null
        $ChooseButton.IsEnabled = $true
        $ClearButton.IsEnabled = $true
        $AnalyzeButton.IsEnabled = (Test-EmlFile -Path $script:SelectedEmlPath).Valid
    }
})
$ClearButton.Add_Click({
    $script:SelectedEmlPath = $null
    $FilePathBox.Text = ''
    $AnalyzeButton.IsEnabled = $false
    Clear-Results
    Set-Status -Text ''
})
Clear-Results
[void]$window.ShowDialog()
