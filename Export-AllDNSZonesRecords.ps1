####################################################################################################
# Script Name : Export-AllDNSZonesRecords.ps1
# Owner       : Cedric KAMEGNI
# Description : Exporte tous les enregistrements DNS de toutes les zones d'un serveur DNS
#               Active Directory vers un fichier CSV.
# Prérequis  :
# - Exécuter avec des droits d'administrateur sur un contrôleur de domaine ou serveur DNS.
# - PowerShell ISE ou console PowerShell avec module DNSServer disponible.
####################################################################################################

# Initialisation du rapport
$Report = [System.Collections.Generic.List[Object]]::new()

# Récupération de toutes les zones DNS sur le serveur
$zones = Get-DnsServerZone

foreach ($zone in $zones) {
    # Récupération de tous les enregistrements pour chaque zone
    $zoneInfo = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName

    foreach ($info in $zoneInfo) {

        # Gestion du timestamp
        $timestamp = if ($info.Timestamp) { $info.Timestamp } else { "static" }

        # Temps de vie de l'enregistrement en secondes
        $timetolive = $info.TimeToLive.TotalSeconds

        # Récupération des données selon le type d'enregistrement
        $recordData = switch ($info.RecordType) {
            'A'     { $info.RecordData.IPv4Address }
            'AAAA'  { $info.RecordData.IPv6Address }
            'CNAME' { $info.RecordData.HostnameAlias }
            'NS'    { $info.RecordData.NameServer }
            'SOA'   { "[$($info.RecordData.SerialNumber)] $($info.RecordData.PrimaryServer), $($info.RecordData.ResponsiblePerson)" }
            'SRV'   { $info.RecordData.DomainName }
            'PTR'   { $info.RecordData.PtrDomainName }
            'MX'    { $info.RecordData.MailExchange }
            'TXT'   { $info.RecordData.DescriptiveText }
            default { $null }
        }

        # Création de l'objet PowerShell pour l'export
        $ReportLine = [PSCustomObject]@{
            ZoneName   = $zone.ZoneName
            Hostname   = $info.Hostname
            Type       = $info.RecordType
            Data       = $recordData
            Timestamp  = $timestamp
            TimeToLive = $timetolive
        }

        # Ajout de la ligne au rapport
        $Report.Add($ReportLine)
    }
}

# Export du rapport complet en CSV
$ExportPath = "C:\temp\AllDNSZonesRecords.csv"
$Report | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

Write-Host "✔ Export terminé : $ExportPath" -ForegroundColor Green
