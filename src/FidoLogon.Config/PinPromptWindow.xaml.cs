using System.Windows;
using FidoLogon.Core;

namespace FidoLogon.Config;

public partial class PinPromptWindow : Window
{
    public PinPromptWindow()
    {
        InitializeComponent();
    }

    /// <summary>Optional explanation shown under the question (why the PIN is needed).</summary>
    public string Detail
    {
        set => Show(DetailText, value);
    }

    /// <summary>Optional error of the previous attempt, for example an incorrect PIN.</summary>
    public string Error
    {
        set => Show(ErrorText, value);
    }

    /// <summary>Copies the typed PIN out of the box and clears it; the caller disposes the result.</summary>
    public SecretText TakePin()
    {
        SecretText pin = SecretText.FromSecureString(PinBox.SecurePassword);
        PinBox.Clear();
        return pin;
    }

    private void OnOkClicked(object sender, RoutedEventArgs e)
    {
        if (PinBox.SecurePassword.Length == 0)
        {
            Error = "Enter the PIN.";
            return;
        }
        DialogResult = true;
    }

    private static void Show(System.Windows.Controls.TextBlock block, string text)
    {
        block.Text = text;
        block.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
    }
}
