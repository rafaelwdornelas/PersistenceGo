# PersistenceGo

**AVISO:**  
Este projeto demonstra técnicas de persistência no Windows por meio de modificações no registro – uma atividade que pode comprometer a segurança e a estabilidade do sistema se utilizada de forma indevida.  
**Utilize este código apenas para fins educativos e em ambientes de teste.**  
O autor não se responsabiliza por qualquer dano decorrente do uso deste projeto.

---

## Descrição

O **PersistenceGo** é um projeto desenvolvido em Go que implementa 50 funções, cada uma representando uma técnica de persistência no Windows. Estas funções, em sua maioria, interagem com o registro do Windows para configurar a execução automática de um executável (por exemplo, `C:\Users\teste\teste.exe`) em diferentes fases do boot, logon ou outros eventos do sistema.

Este projeto serve como uma base didática para demonstrar como diversas técnicas – inspiradas em ferramentas como o PersistenceSniper – podem ser implementadas em Go.

---

## Funcionalidades

A seguir, uma lista detalhada das 50 funções disponíveis no projeto:

1. **AddRunPersistenceHKLM**  
   Insere uma entrada em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` para execução automática do programa no boot (para todos os usuários).

2. **AddRunPersistenceHKCU**  
   Insere uma entrada em `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` para execução automática no logon do usuário atual.

3. **AddRunOncePersistenceHKLM**  
   Insere uma entrada em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` para execução única no boot.

4. **AddRunOncePersistenceHKCU**  
   Insere uma entrada em `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` para execução única no logon.

5. **AddIFEO**  
   Utiliza a técnica de Image File Execution Options para redirecionar a execução de um programa específico (ex.: `notepad.exe`) para um executável customizado.

6. **AddNLDPDllOverride**  
   Define o valor `DLLPathOverride` em `SYSTEM\CurrentControlSet\Control\ContentIndex\Language\<subkey>` para carregar uma DLL customizada.

7. **SetAEDebugDebugger**  
   Modifica a chave `AeDebug\Debugger` em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug` para definir um depurador personalizado.

8. **SetWerFaultHangsDebugger**  
   Configura a chave `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs\Debugger` para alterar o comportamento do Windows Error Reporting em caso de falha.

9. **AddCmdAutoRunPersistenceHKLM**  
   Define o valor `AutoRun` na chave `HKEY_LOCAL_MACHINE\Software\Microsoft\Command Processor` para o Command Processor iniciar automaticamente um comando.

10. **AddCmdAutoRunPersistenceHKCU**  
    Define o valor `AutoRun` na chave `HKEY_CURRENT_USER\Software\Microsoft\Command Processor` para o Command Processor no contexto do usuário atual.

11. **SetExplorerLoad**  
    Configura o valor `Load` em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` para forçar o Explorer a carregar um executável adicional.

12. **SetWinlogonUserinit**  
    Altera o valor `Userinit` em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` para incluir um executável no processo de logon (normalmente concatenado com o valor padrão).

13. **SetWinlogonShell**  
    Modifica o valor `Shell` em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` para definir um shell customizado (em substituição ao padrão, normalmente `explorer.exe`).

14. **SetAppCertDlls**  
    Insere uma entrada customizada em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` para carregar uma DLL durante o boot dos processos.

15. **SetServiceDll**  
    Altera a entrada `ServiceDll` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<Nome_do_Serviço>\Parameters` para que um serviço carregue uma DLL personalizada.

16. **SetGPExtensionDll**  
    Modifica o valor `DllName` na chave `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\<GUID>` para utilizar uma DLL customizada na Política de Grupo.

17. **SetWinlogonMPNotify**  
    Configura o valor `mpnotify` em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` para executar um programa durante o logon.

18. **SetCHMHelperDll**  
    Define a localização da DLL em `HKEY_LOCAL_MACHINE\Software\Microsoft\HtmlHelp Author\Location`, alterando o comportamento do mecanismo de ajuda (CHM).

19. **SetHHCtrlHijacking**  
    Modifica o valor `(Default)` em `HKEY_CLASSES_ROOT\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32` para redirecionar a carga da DLL `hhctrl.ocx`.

20. **CreateStartupFolderShortcut**  
    *(Não implementada)*  
    Representa a criação de um atalho na pasta Startup para execução automática – esta técnica é baseada em arquivos e não em registro.

21. **AddUserInitMprLogonScriptHKLM**  
    Insere ou modifica o valor `UserInitMprLogonScript` na chave `HKEY_LOCAL_MACHINE\Environment` para executar um script no logon.

22. **AddUserInitMprLogonScriptHKCU**  
    Insere ou modifica o valor `UserInitMprLogonScript` na chave `HKEY_CURRENT_USER\Environment`.

23. **SetAutodialDLL**  
    Define o valor `AutodialDLL` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters` para injetar uma DLL via Winsock.

24. **SetLSAExtensionsDLL**  
    Configura as extensões do LSA alterando o valor `Extensions` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv`.

25. **SetServerLevelPluginDll**  
    Modifica a chave `ServerLevelPluginDll` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters` para injetar uma DLL no serviço DNS.

26. **SetLSAPasswordFilterDLL**  
    Altera o valor `Notification Packages` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` para carregar um filtro de senha customizado.

27. **SetLSAAuthenticationPackages**  
    Modifica o valor `Authentication Packages` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` para alterar os pacotes de autenticação do sistema.

28. **SetLSASecurityPackages**  
    Altera o valor `Security Packages` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` para modificar os pacotes de segurança.

29. **SetWinlogonNotificationPackages**  
    Insere uma entrada na chave `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify` para configurar um pacote de notificação.

30. **SetExplorerTools**  
    Altera o valor `(Default)` em uma subchave de `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer` para injetar um executável customizado.

31. **SetDotNetDebugger**  
    Configura o depurador para aplicações .NET modificando o valor `DbgManagedDebugger` tanto em  
    `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework` quanto em  
    `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework`.

32. **AddRunExPersistence**  
    Insere uma entrada na chave alternativa `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx`.

33. **SetAppPath**  
    Define o caminho padrão para um aplicativo em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<Nome_do_App>`.

34. **SetTerminalServicesInitialProgramPolicy**  
    Modifica o valor `InitialProgram` em `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` para definir um programa a ser iniciado em sessões RDP via política.

35. **SetTerminalServicesInitialProgramWinStations**  
    Altera o valor `InitialProgram` em `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`.

36. **SetAMSIProvider**  
    Configura um provedor AMSI falso, modificando o valor `(Default)` na chave  
    `HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\<GUID>\InprocServer32`.

37. **SetPowershellProfile**  
    *(Não implementada)*  
    Técnica que normalmente modifica arquivos de perfil do PowerShell (não baseada em registro).

38. **SetSilentExitMonitor**  
    Altera o valor `MonitorProcess` em uma subchave de  
    `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`.

39. **SetTelemetryControllerCommand**  
    Configura o valor `Command` em  
    `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController`.

40. **SetRDPWDSStartupPrograms**  
    Modifica o valor `StartupPrograms` em  
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd`.

41. **SetDotNetStartupHooks**  
    Define a variável de ambiente `DOTNET_STARTUP_HOOKS` via registro em  
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`.

42. **SetDsrmBackdoor**  
    Altera o valor `DsrmAdminLogonBehavior` em  
    `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` para possibilitar acesso via DSRM.

43. **SetGhostTask**  
    *(Não implementada)*  
    Técnica avançada que envolve parsing e modificação de chaves de tarefas agendadas “fantasma” no registro.

44. **SetBootVerificationProgramHijacking**  
    Modifica o valor `ImagePath` em  
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BootVerificationProgram` para substituir o programa de verificação do boot.

45. **SetAppInitDLLs**  
    Configura a chave `AppInit_DLLs` em  
    `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows` para sistemas 64-bit.

46. **SetAppInitDLLsWow6432**  
    Configura a chave `AppInit_DLLs` em  
    `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` para sistemas 32-bit em ambiente 64-bit.

47. **SetBootExecute**  
    Altera o valor `BootExecute` em  
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager` para executar comandos no boot.

48. **SetNetshHelperDLL**  
    Insere uma entrada personalizada em  
    `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh` para que o netsh.exe carregue uma DLL customizada.

49. **SetSetupExecute**  
    Modifica o valor `SetupExecute` em  
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager` para injetar comandos durante o processo de setup.

50. **SetPlatformExecute**  
    Altera o valor `PlatformExecute` em  
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager` para definir comandos executados pelo Session Manager no boot.

---

## Requisitos

- **Go:** Versão 1.16 ou superior (recomendada).
- **Ambiente Windows:** O projeto deve ser executado no Windows.
- **Privilégios Administrativos:** Necessários para modificar chaves em `HKEY_LOCAL_MACHINE`.
- **Dependência:** [golang.org/x/sys/windows/registry](https://pkg.go.dev/golang.org/x/sys/windows/registry)

---

## Como Usar

1. **Clone o repositório:**

   ```bash
   git clone https://github.com/rafaelwdornelas/PersistenceGo.git
   cd PersistenceGo  ```
   
2. **Compile o projeto:**

   ```bash
   go build -o persistencego.exe main.go```
   
3. **Execute o programa com privilégios administrativos:**

Execute o persistencego.exe no Windows (como administrador). O programa tentará configurar cada uma das 50 técnicas de persistência apontando para o executável C:\Users\teste\teste.exe.

Atenção:
Alterações no registro podem afetar o funcionamento do sistema. Use este projeto apenas em ambientes de teste e com extremo cuidado!

