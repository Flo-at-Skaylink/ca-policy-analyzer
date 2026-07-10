export default function OfflineExportGuidePage() {
  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-2xl font-bold text-white">Offline Export Guide</h2>
        <p className="mt-2 text-sm text-gray-400">
          Use this workflow when CA Policy Analyzer cannot access Microsoft Graph directly.
          Export once from an online admin workstation, then import the JSON file into offline mode.
        </p>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 space-y-4">
        <h3 className="text-lg font-semibold text-white">1) Prepare PowerShell</h3>
        <p className="text-sm text-gray-400">
          Run these commands on a workstation that can reach Microsoft Graph.
          This installs only the required submodules.
        </p>
        <pre className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs text-gray-300">
{`Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Identity.SignIns -Scope CurrentUser
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser

Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Beta.Identity.SignIns
Import-Module Microsoft.Graph.Applications
Import-Module Microsoft.Graph.Identity.DirectoryManagement`}
        </pre>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 space-y-4">
        <h3 className="text-lg font-semibold text-white">2) Run export script</h3>
        <p className="text-sm text-gray-400">
          This creates a single file named <code>ca-offline-export.json</code> with
          all required datasets.
        </p>
        <pre className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs text-gray-300">
{`Connect-MgGraph -Scopes \`
  "Policy.Read.All", \`
  "Application.Read.All", \`
  "Directory.Read.All", \`
  "Policy.Read.ConditionalAccess", \`
  "Organization.Read.All"

$tenant = Get-MgOrganization -Top 1
$policies = Get-MgBetaIdentityConditionalAccessPolicy -All
$namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
$servicePrincipals = Get-MgServicePrincipal -All -Property "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,tags"
$authStrengthPolicies = Get-MgBetaPolicyAuthenticationStrengthPolicy -All
$subscribedSkus = Get-MgSubscribedSku -All

$objectIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($p in $policies) {
  $u = $p.Conditions.Users
  foreach ($id in @($u.IncludeUsers + $u.ExcludeUsers + $u.IncludeGroups + $u.ExcludeGroups + $u.IncludeRoles + $u.ExcludeRoles)) {
    if ($id -match '^[0-9a-fA-F-]{36}$') { [void]$objectIds.Add($id) }
  }
}

$directoryObjects = foreach ($id in $objectIds) {
  try { Get-MgDirectoryObject -DirectoryObjectId $id -ErrorAction Stop } catch { $null }
}

$export = [ordered]@{
  tenantId                       = $tenant.Id
  tenantDisplayName              = $tenant.DisplayName
  conditionalAccessPolicies      = $policies
  namedLocations                 = $namedLocations
  servicePrincipals              = $servicePrincipals
  directoryObjects               = $directoryObjects
  authenticationStrengthPolicies = $authStrengthPolicies
  subscribedSkus                 = $subscribedSkus
}

$export | ConvertTo-Json -Depth 25 | Out-File ".\\ca-offline-export.json" -Encoding utf8`}
        </pre>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 space-y-3">
        <h3 className="text-lg font-semibold text-white">3) Import into analyzer</h3>
        <ol className="list-decimal space-y-2 pl-5 text-sm text-gray-300">
          <li>Open CA Policy Analyzer.</li>
          <li>On the landing screen, click <strong>Import Offline Export</strong>.</li>
          <li>Select <code>ca-offline-export.json</code>.</li>
          <li>Run analysis as usual.</li>
        </ol>
      </div>
    </div>
  );
}
