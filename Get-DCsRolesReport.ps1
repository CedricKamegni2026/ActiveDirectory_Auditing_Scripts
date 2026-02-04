
########################################################################################################################
###Que fait ce script ?

###Ce script PowerShell permet de récupérer tous les rôles Windows installés sur chaque contrôleur de domaine (DC) de votre forêt Active Directory et de les afficher de manière lisible.

###Voici comment exécuter ton script PowerShell pour récupérer les rôles installés sur tous les contrôleurs de domaine et exporter les résultats :

###1?? Préparer le script

###Copie tout ton code dans un fichier texte et enregistre-le avec l’extension .ps1, par exemple :

###Get-DCsRolesReport.ps1


###Assure-toi que le script est sur un serveur ou poste avec le module ActiveDirectory installé et que tu as les droits nécessaires pour interroger tous les DC.

######################################################################################################

#Get Installed Roles on each Domain Controller
$DCsInForest = (Get-ADForest).Domains | % {Get-ADDomainController -Filter * -Server $_}
$DCsRolesArray = @()
foreach ($DC in $DCsInForest) {
    $DCRoles=""
    $Roles = Get-WindowsFeature -ComputerName $DC.HostName | Where-Object {$_.Installed -like "True" -and $_.FeatureType -like "Role"} | Select DisplayName
    foreach ($Role in $Roles) {
        $DCRoles += $Role.DisplayName +","
    }
    try {$DCRoles = $DCRoles.Substring(0,$DCRoles.Length-1)}
    catch {$DCRoles = "Server roles cannot be obtain"}
    $DCObject = New-Object -TypeName PSObject
    Add-Member -InputObject $DCObject -MemberType 'NoteProperty' -Name 'DCName' -Value $DC.HostName
    Add-Member -InputObject $DCObject -MemberType 'NoteProperty' -Name 'Roles' -Value $DCRoles
    $DCsRolesArray += $DCObject
}
$DCsRolesArray | Out-GridView

# ------------------------------
# Export automatique dans un CSV
# ------------------------------
$csvPath = ".\$((Get-ADForest).Name)_DC_Roles_Report.csv"
$DCsRolesArray | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "Report exported to $csvPath" -ForegroundColor Green


