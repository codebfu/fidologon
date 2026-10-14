using System.ServiceProcess;
using FidoLogon.Service;

if (Environment.UserInteractive)
{
    Console.Error.WriteLine("FidoLogon.Service runs as a Windows service (installed by the FidoLogon MSI).");
    return 1;
}

ServiceBase.Run(new FidoLogonService());
return 0;
