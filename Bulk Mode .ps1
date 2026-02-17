.\Remove-AvdHostsFully.ps1 `
-SubscriptionId "<SubscriptionId>" `
-AvdResourceGroup "RG-AVD" `
-HostPoolName "PROD-POOL" `
-BulkFile ".\hosts.csv" `
  -WaitForZeroSessions `
  -TimeoutMinutes 30 `
-Execute
