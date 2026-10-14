using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FidoLogon.Core;

namespace FidoLogon.Config;

public partial class EnrollWindow : Window
{
    private SecurityKeyCapabilities? _capabilities;

    public EnrollWindow()
    {
        InitializeComponent();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            AccountCombo.ItemsSource = FidoLogonApi.ListLocalAccounts().Where(a => !a.Disabled).ToList();
            string current = Environment.UserName;
            AccountCombo.SelectedItem = AccountCombo.Items.Cast<LocalAccount>()
                .FirstOrDefault(a => string.Equals(a.Name, current, StringComparison.OrdinalIgnoreCase));
        }
        catch (FidoLogonException ex)
        {
            ShowStatus(ex.Message, isError: true);
        }
        RefreshDevices();
    }

    private void OnRefreshDevicesClicked(object sender, RoutedEventArgs e) => RefreshDevices();

    private void RefreshDevices()
    {
        try
        {
            IReadOnlyList<SecurityKeyDevice> devices = FidoLogonApi.ListDevices();
            DeviceCombo.ItemsSource = devices;
            DeviceCombo.SelectedIndex = devices.Count > 0 ? 0 : -1;
            if (devices.Count == 0)
            {
                DeviceInfo.Text = "No security key detected. Plug in a key and click Refresh.";
            }
        }
        catch (FidoLogonException ex)
        {
            DeviceInfo.Text = ex.Message;
        }
    }

    private void OnDeviceChanged(object sender, SelectionChangedEventArgs e)
    {
        _capabilities = null;
        if (DeviceCombo.SelectedItem is not SecurityKeyDevice device)
        {
            return;
        }
        try
        {
            _capabilities = FidoLogonApi.GetCapabilities(device.Path);
            DeviceInfo.Text = !_capabilities.HmacSecret
                ? "This key does not support the hmac-secret extension and cannot be used."
                : !_capabilities.HasPin
                    ? "No PIN set on the key: only touch-only mode is possible (or set a PIN with the key vendor's tool)."
                    : !_capabilities.CredProtect
                        ? "This key cannot enforce its PIN (no CTAP 2.1 credProtect): only touch-only mode is possible."
                        : "PIN set on the key.";
        }
        catch (FidoLogonException ex)
        {
            DeviceInfo.Text = ex.Message;
        }
    }

    private async void OnEnrollClicked(object sender, RoutedEventArgs e)
    {
        if (AccountCombo.SelectedItem is not LocalAccount account)
        {
            ShowStatus("Choose an account.", isError: true);
            return;
        }
        if (DeviceCombo.SelectedItem is not SecurityKeyDevice device || _capabilities is null)
        {
            ShowStatus("Plug in and choose a security key.", isError: true);
            return;
        }
        if (!_capabilities.HmacSecret)
        {
            ShowStatus("This key cannot be used (no hmac-secret support).", isError: true);
            return;
        }
        UnlockMode mode = PinModeRadio.IsChecked == true ? UnlockMode.PinAndTouch : UnlockMode.TouchOnly;
        if (mode == UnlockMode.PinAndTouch && !_capabilities.HasPin)
        {
            ShowStatus("PIN mode needs a PIN set on the key.", isError: true);
            return;
        }
        if (mode == UnlockMode.PinAndTouch && !_capabilities.CredProtect)
        {
            ShowStatus("PIN mode needs a key that supports CTAP 2.1 credProtect. Use touch-only mode with this key.",
                isError: true);
            return;
        }
        if (PasswordBox.SecurePassword.Length == 0)
        {
            ShowStatus("Enter the account's Windows password.", isError: true);
            return;
        }

        string label = LabelBox.Text;
        bool? lockOnRemoval = RemovalCombo.SelectedIndex switch
        {
            1 => true,
            2 => false,
            _ => null,
        };
        SecretText password = SecretText.FromSecureString(PasswordBox.SecurePassword);
        IsEnabled = false;
        try
        {
            string? pinError = null;
            while (true)
            {
                // A key with a PIN needs it to create the credential, even in touch-only mode.
                SecretText pin = SecretText.Empty();
                if (_capabilities.HasPin)
                {
                    pin.Dispose();
                    if (AskPin(mode, pinError) is not { } typed)
                    {
                        ShowStatus("", isError: false);
                        return;
                    }
                    pin = typed;
                }
                using (pin)
                {
                    ShowStatus("Enrolling the key…", isError: false);
                    var prompt = new TouchPromptWindow { Owner = this };
                    void OnTouch(int touch, int total) => Dispatcher.Invoke(() => prompt.ShowTouch(touch, total,
                        touch == 1
                            ? "Creating the sign-in credential on the key."
                            : "Deriving the key that encrypts the Windows password."));
                    try
                    {
                        string id = await Task.Run(() =>
                            EnrollmentService.Enroll(device, account, label, mode, pin, password, OnTouch));
                        if (lockOnRemoval is not null)
                        {
                            FidoLogonApi.SetKeyLockOnRemoval(id, lockOnRemoval);
                        }
                        DialogResult = true;
                        return;
                    }
                    catch (FidoLogonException ex) when (ex.Code == FidoLogonErrorCode.PinInvalid && _capabilities.HasPin)
                    {
                        pinError = ex.Message;  // asked again
                    }
                    catch (FidoLogonException ex)
                    {
                        ShowStatus(ex.Message, isError: true);
                        return;
                    }
                    finally
                    {
                        prompt.Close();
                    }
                }
            }
        }
        finally
        {
            password.Dispose();
            IsEnabled = true;
        }
    }

    /// <summary>Asks for the key's PIN in a popup; null when cancelled. The caller disposes the result.</summary>
    private SecretText? AskPin(UnlockMode mode, string? error)
    {
        var prompt = new PinPromptWindow
        {
            Owner = this,
            Detail = mode == UnlockMode.TouchOnly
                ? "Needed once to create the credential: signing in will then only need a touch."
                : "It will be asked at each sign-in, before touching the key.",
            Error = error ?? "",
        };
        return prompt.ShowDialog() == true ? prompt.TakePin() : null;
    }

    private void ShowStatus(string text, bool isError)
    {
        StatusText.Text = text;
        StatusText.Foreground = isError ? Brushes.Firebrick : Brushes.DimGray;
    }
}
