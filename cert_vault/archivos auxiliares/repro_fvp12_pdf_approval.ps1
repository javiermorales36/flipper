param(
    [ValidateSet('request', 'status', 'simulate-approve', 'simulate-reject', 'finalize', 'health', 'wait', 'help')]
    [string]$Action = 'help',

    [string]$BaseUrl = 'http://127.0.0.1:8766',
    [string]$InputPdf,
    [string]$OutputPdf,
    [string]$Reason = 'Prueba aprobacion Flipper',
    [string]$FieldName = 'Signature1',
    [string]$RequestId,
    [string]$ExchangeDir = 'approval_exchange_test',
    [switch]$Usb,
    [int]$PollSeconds = 2,
    [int]$TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    [Console]::Error.WriteLine("[step] $Message")
}

function Show-Usage {
        @"
Usage:
    pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action health -Usb
    pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action request -Usb -InputPdf .\approval_test_unsigned.pdf -OutputPdf .\approval_test_signed_usb.pdf
    pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action status -RequestId <ID>
    pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action wait -RequestId <ID> -TimeoutSeconds 300
    pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action finalize -Usb -RequestId <ID>

Actions:
    help               Show this help text.
    health             Show service and bridge status.
    request            Create a pending PDF signing request.
    status             Query the status of a request.
    wait               Poll until the request is approved or rejected.
    finalize           Finalize the PDF signing after approval.
    simulate-approve   Write a local simulated approval response.
    simulate-reject    Write a local simulated rejection response.

Options:
    -Usb               Require the service to be running with the USB bridge active.
    -BaseUrl           Service URL. Default: http://127.0.0.1:8766
    -InputPdf          Input PDF for request.
    -OutputPdf         Output path for request/finalize flow.
    -RequestId         Request identifier for status/wait/finalize/simulate actions.
    -PollSeconds       Poll interval for wait. Default: 2
    -TimeoutSeconds    Wait timeout. Default: 300
"@
}

function Require-RequestId {
    if([string]::IsNullOrWhiteSpace($RequestId)) {
        throw 'RequestId is required for this action.'
    }
}

function Resolve-WorkspacePath {
    param([string]$PathValue)

    if([string]::IsNullOrWhiteSpace($PathValue)) {
        return $null
    }

    return (Resolve-Path $PathValue).Path
}

function Get-ServiceHealthObject {
    return Invoke-RestMethod -Uri "$BaseUrl/health"
}

function Get-ServiceHealth {
    Write-Step 'Querying service health'
    $response = Get-ServiceHealthObject
    $response | ConvertTo-Json
}

function Assert-UsbBridge {
    if(-not $Usb) {
        return
    }

    $health = Get-ServiceHealthObject
    if($health.flipper_bridge_mode -ne 'usb') {
        throw "The service is not running in USB mode. Current mode: $($health.flipper_bridge_mode)"
    }

    if(-not $health.flipper_bridge_active) {
        $detail = if([string]::IsNullOrWhiteSpace([string]$health.flipper_bridge_error)) {
            'USB bridge is inactive.'
        } else {
            [string]$health.flipper_bridge_error
        }
        throw "The USB bridge is not active. $detail"
    }
}

function Request-PdfApproval {
    if([string]::IsNullOrWhiteSpace($InputPdf)) {
        throw 'InputPdf is required for action=request.'
    }

    Assert-UsbBridge

    $resolvedInput = Resolve-WorkspacePath $InputPdf
    $resolvedOutput = if([string]::IsNullOrWhiteSpace($OutputPdf)) { $null } else { (Resolve-Path -LiteralPath (Split-Path -Parent $OutputPdf) -ErrorAction SilentlyContinue) | Out-Null; $OutputPdf }

    $body = @{
        input_path = $resolvedInput
        reason = $Reason
        field_name = $FieldName
    }

    if(-not [string]::IsNullOrWhiteSpace($OutputPdf)) {
        $body.output_path = [System.IO.Path]::GetFullPath($OutputPdf)
    }

    Write-Step 'Creating pending PDF signing request'
    $response = Invoke-RestMethod -Uri "$BaseUrl/request-sign-pdf" -Method Post -ContentType 'application/json' -Body (($body | ConvertTo-Json -Compress))
    $response | ConvertTo-Json
}

function Get-ApprovalStatus {
    Require-RequestId
    Write-Step 'Querying approval status'
    $response = Invoke-RestMethod -Uri "$BaseUrl/approval-status/$RequestId"
    $response | ConvertTo-Json
}

function Wait-ApprovalDecision {
    Require-RequestId

    $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
    Write-Step "Waiting for approval decision (timeout: $TimeoutSeconds seconds)"

    while((Get-Date).ToUniversalTime() -lt $deadline) {
        $response = Invoke-RestMethod -Uri "$BaseUrl/approval-status/$RequestId"
        if($response.status -ne 'pending') {
            $response | ConvertTo-Json
            return
        }

        Start-Sleep -Seconds $PollSeconds
    }

    throw "Timed out waiting for approval decision for request $RequestId after $TimeoutSeconds seconds."
}

function Write-SimulatedResponse {
    param([string]$Decision)

    Require-RequestId

    $responsesDir = Join-Path $ExchangeDir 'responses'
    New-Item -ItemType Directory -Force -Path $responsesDir | Out-Null
    $responsePath = Join-Path $responsesDir "$RequestId.resp"
    $content = @(
        'format=FVP12-RESP-1'
        "request_id=$RequestId"
        "decision=$Decision"
        'decided_at=simulated-powershell'
        'device=flipper'
        ''
    ) -join [Environment]::NewLine

    Write-Step "Writing simulated $Decision response"
    Set-Content -LiteralPath $responsePath -Value $content -Encoding utf8
    Write-Output $responsePath
}

function Finalize-PdfSigning {
    Require-RequestId
    Assert-UsbBridge
    Write-Step 'Finalizing PDF signing after approval'
    $body = @{ request_id = $RequestId }
    $response = Invoke-RestMethod -Uri "$BaseUrl/finalize-sign-pdf" -Method Post -ContentType 'application/json' -Body (($body | ConvertTo-Json -Compress))
    $response | ConvertTo-Json
}

switch($Action) {
    'help' { Show-Usage }
    'health' { Get-ServiceHealth }
    'request' { Request-PdfApproval }
    'status' { Get-ApprovalStatus }
    'wait' { Wait-ApprovalDecision }
    'simulate-approve' { Write-SimulatedResponse -Decision 'approved' }
    'simulate-reject' { Write-SimulatedResponse -Decision 'rejected' }
    'finalize' { Finalize-PdfSigning }
    default { throw "Unsupported action: $Action" }
}