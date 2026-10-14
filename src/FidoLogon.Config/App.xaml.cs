using System.Windows;
using System.Windows.Threading;

namespace FidoLogon.Config;

public partial class App : Application
{
    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.Message, "FidoLogon", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
