# HostSet
Written because Windows 8's OOBE wizard let me set the hostname in title-case, something PowerShell's `Set-ComputerName` and sysdm.cpl has never let me do, and now that the option has been entirely removed from Windows 10's OOBE...

Run `HostSetOOBE <Hostname>` (this can be in title-case; `SetComputerNameEx` will make sure the cases are correct where necessary, the NetBIOS name is always set as uppercase) and reboot.

Run `HostSetOOBE /POST <Hostname>` and reboot again.
