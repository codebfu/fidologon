using System.Windows;
using System.Windows.Controls;
using FidoLogon.Core;

namespace FidoLogon.Config;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private sealed record KeyRow(string Id, string UserName, string Label, string Mode, string Removal,
        string Model, string Created, bool RequirePin, bool? LockOnRemoval);

    private KeyRow? SelectedKey => KeysGrid.SelectedItem as KeyRow;

    // Set while the removal combo box is updated from code, to ignore its SelectionChanged.
    private bool _updatingRemovalCombo;

    private void OnLoaded(object sender, RoutedEventArgs e) => Reload();

    private void OnRefreshClicked(object sender, RoutedEventArgs e) => Reload();

    private void Reload()
    {
        try
        {
            bool lockByDefault = FidoLogonApi.LockOnKeyRemoval;
            Dictionary<string, string> modelNames = FidoLogonApi.ListAllowedModels()
                .ToDictionary(m => m.Aaguid, m => m.Description, StringComparer.OrdinalIgnoreCase);
            KeysGrid.ItemsSource = FidoLogonApi.ListEnrolledKeys()
                .Select(k => new KeyRow(k.Id, k.UserName, k.Label, k.RequirePin ? "PIN + touch" : "Touch only",
                    DescribeRemoval(k.LockOnRemoval, lockByDefault),
                    modelNames.GetValueOrDefault(k.Aaguid, k.Aaguid), k.Created.LocalDateTime.ToString("d"),
                    k.RequirePin, k.LockOnRemoval))
                .ToList();
            FallbackCheckBox.IsChecked = FidoLogonApi.AllowPasswordFallback;
            LockCheckBox.IsChecked = lockByDefault;
            UpdateFallbackWarning();
            StatusText.Text = string.Empty;
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
        OnSelectionChanged(this, null);
    }

    private void UpdateFallbackWarning()
    {
        if (FallbackCheckBox.IsChecked == true)
        {
            FallbackWarning.Visibility = Visibility.Collapsed;
            return;
        }
        FallbackWarning.Text = FidoLogonApi.IsMachineJoined()
            ? "Not effective: this computer is joined to a domain or Entra ID, so the password tile stays visible."
            : FidoLogonApi.EveryEnabledAccountHasKey()
            ? "The password tile is hidden at sign-in. Keep a backup key enrolled for every account and read the recovery guide."
            : "Not effective yet: the password tile stays visible until every enabled local account has at least one key.";
        FallbackWarning.Visibility = Visibility.Visible;
    }

    private static string DescribeRemoval(bool? lockOnRemoval, bool lockByDefault) => lockOnRemoval switch
    {
        null => lockByDefault ? "Lock (default)" : "Nothing (default)",
        true => "Lock",
        false => "Nothing",
    };

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs? e)
    {
        TestButton.IsEnabled = SelectedKey is not null;
        RemoveButton.IsEnabled = SelectedKey is not null;
        RemovalCombo.IsEnabled = SelectedKey is not null;
        _updatingRemovalCombo = true;
        RemovalCombo.SelectedIndex = SelectedKey?.LockOnRemoval switch
        {
            null when SelectedKey is null => -1,
            null => 0,
            true => 1,
            false => 2,
        };
        _updatingRemovalCombo = false;
    }

    private void OnRemovalChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingRemovalCombo || SelectedKey is not { } key || RemovalCombo.SelectedIndex < 0)
        {
            return;
        }
        bool? lockOnRemoval = RemovalCombo.SelectedIndex switch
        {
            1 => true,
            2 => false,
            _ => null,
        };
        if (lockOnRemoval == key.LockOnRemoval)
        {
            return;
        }
        try
        {
            FidoLogonApi.SetKeyLockOnRemoval(key.Id, lockOnRemoval);
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
        Reload();
        KeysGrid.SelectedItem = KeysGrid.Items.Cast<KeyRow>().FirstOrDefault(r => r.Id == key.Id);
        StatusText.Text = "Removal behavior updated.";
    }

    private void OnLockClicked(object sender, RoutedEventArgs e)
    {
        bool lockSession = LockCheckBox.IsChecked == true;
        if (!lockSession && MessageBox.Show(this,
                "Stop locking sessions when their key is removed?\n\nKeys set to \"Lock session\" keep locking. " +
                "For the others, remember to lock the session yourself (Win+L) when you leave.",
                "FidoLogon", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            LockCheckBox.IsChecked = true;
            return;
        }
        try
        {
            FidoLogonApi.LockOnKeyRemoval = lockSession;
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
        Reload();
    }

    private void OnModelsClicked(object sender, RoutedEventArgs e)
    {
        new ModelsWindow { Owner = this }.ShowDialog();
        Reload();
    }

    private void OnAddClicked(object sender, RoutedEventArgs e)
    {
        var dialog = new EnrollWindow { Owner = this };
        if (dialog.ShowDialog() == true)
        {
            Reload();
            StatusText.Text = "Key enrolled.";
        }
    }

    private async void OnTestClicked(object sender, RoutedEventArgs e)
    {
        if (SelectedKey is not { } key)
        {
            return;
        }
        SecretText pin = SecretText.Empty();
        if (key.RequirePin)
        {
            var prompt = new PinPromptWindow { Owner = this };
            if (prompt.ShowDialog() != true)
            {
                pin.Dispose();
                return;
            }
            pin.Dispose();
            pin = prompt.TakePin();
        }
        IsEnabled = false;
        StatusText.Text = "Looking for the security key…";
        var touchPrompt = new TouchPromptWindow { Owner = this };
        void OnTouch(int touch, int total) => Dispatcher.Invoke(() =>
            touchPrompt.ShowTouch(touch, total, "Checking that the key unlocks the stored password."));
        FidoLogonException? error = null;
        try
        {
            await Task.Run(() => FidoLogonApi.TestEnrolledKey(key.Id, pin, OnTouch));
        }
        catch (FidoLogonException ex)
        {
            error = ex;
        }
        finally
        {
            touchPrompt.Close();
            pin.Dispose();
            IsEnabled = true;
            StatusText.Text = string.Empty;
        }
        if (error is null)
        {
            MessageBox.Show(this, "The key unlocks the stored credential.", "FidoLogon", MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        else
        {
            ShowError(error.Code == FidoLogonErrorCode.DecryptFailed
                ? "This key no longer unlocks the stored password. Remove it and enroll it again."
                : error.Message);
        }
    }

    private void OnRemoveClicked(object sender, RoutedEventArgs e)
    {
        if (SelectedKey is not { } key)
        {
            return;
        }
        if (MessageBox.Show(this, $"Remove key \"{key.Label}\" of {key.UserName}?", "FidoLogon",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }
        try
        {
            FidoLogonApi.RemoveEnrolledKey(key.Id);
            Reload();
            StatusText.Text = "Key removed.";
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
    }

    private void OnFallbackClicked(object sender, RoutedEventArgs e)
    {
        bool allow = FallbackCheckBox.IsChecked == true;
        if (!allow && MessageBox.Show(this,
                "Hide the Windows password tile at sign-in?\n\nIf every key of an account is lost, that account can " +
                "only be recovered from safe mode or the recovery environment (see the recovery guide).",
                "FidoLogon", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            FallbackCheckBox.IsChecked = true;
            return;
        }
        try
        {
            FidoLogonApi.AllowPasswordFallback = allow;
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
        Reload();
    }

    private void ShowError(string message) =>
        MessageBox.Show(this, message, "FidoLogon", MessageBoxButton.OK, MessageBoxImage.Error);
}
