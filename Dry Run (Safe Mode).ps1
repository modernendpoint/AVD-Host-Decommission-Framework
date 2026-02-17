.\Remove-AvdHostsFully.ps1 `
  -SubscriptionId "<sub>" `
  -AvdResourceGroup "RG-AVD" `
  -HostPoolName "POOL" `
  -VmNames @("VM1","VM2")