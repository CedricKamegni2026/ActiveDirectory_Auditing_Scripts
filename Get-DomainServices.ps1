
########################################################################################################################
###Que fait ce script ?

###Ce script recense les services Windows qui s’exécutent avec des comptes de domaine sur tous les serveurs Active Directory.

###Concrètement, il :

###Charge le module ActiveDirectory

###Recherche tous les ordinateurs dont l’OS contient “Server”

###Pour chaque serveur :

###Interroge les services Windows via WMI

###  Sélectionne uniquement les services :

###dont le compte de démarrage (StartName) correspond à un compte de domaine

###Récupère :

###Nom du serveur

###Nom du service

###Compte utilisé (Run As)

###Mode de démarrage

###Exporte les résultats dans un fichier CSV

###Enregistre les serveurs injoignables dans un fichier d’exception

###?? C’est un script d’audit uniquement
###? Il ne modifie rien dans Active Directory ou sur les serveurs.

###Points à adapter AVANT exécution
###1?? Variable $domain
###$domain="*domain*"


###?? À remplacer par ton vrai domaine, par exemple :

###$domain="MONDOMAINE\*"


###ou

###$domain="*@mondomaine.local"

###Lancer le script
###.\Get-DomainServices.ps1
######################################################################################################




### Load the Active Directory Powershell Commands (required)
Import-Module ActiveDirectory
### update the below with the proper values for your environment
$domain="*domain*"
$serviceFile="c:\scripts\services.csv"
$exceptionFile="c:\scripts\exeptions.csv"

if (Test-path $serviceFile) {Clear-Content $serviceFile}
if (test-path $exceptionFile) {Clear-Content $exceptionFile}

##initialize array
$domainservices=@()

## Query AD for all computer objects with "server" in the Operating System
$servers=Get-ADComputer -LDAPFilter "(&(objectcategory=computer)(OperatingSystem=*server*))"

$i=0

## Get a list of all service running as domain users for each server and add to the $domainservices array
foreach ($server in $servers) {
    $i++
    Write-Progress -Activity "Querying Services from Servers" -Status "Percent complete: " -PercentComplete (($i /$servers.Length) * 100)
    $services=try {
        Get-WmiObject win32_service -ComputerName $server.name -ErrorAction Stop | where-object {$_.startname -like $domain} | Select-Object name,startname,startmode
    }
    catch {
       "$server.name could not be contacted" | Out-File -Append $exceptionFile
    }
    foreach ($service in $services) {
        $domserv=[pscustomobject]@{name=$server.name;servicename=$service.name;runasname=$service.startname;startmode=$service.startmode}
        $domainservices += $domserv
    }
    
 }

 ## Output results to CSV file
 $domainservices | Export-Csv -Path $serviceFile -NoTypeInformation