using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using FidoLogon.Core;
using Microsoft.Win32;

namespace FidoLogon.Config;

public partial class ModelsWindow : Window
{
    private readonly KeyModelPolicy _policy = KeyModelPolicy.CreateDefault();
    private MetadataBlob? _metadata;

    public ModelsWindow()
    {
        InitializeComponent();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        LoadMetadata();
        ReloadAllowed();
        ReloadOptions();
    }

    private void ReloadOptions()
    {
        try
        {
            CertifiedCheckBox.IsChecked = FidoLogonApi.AllowCertifiedModels;
            AutoSyncCheckBox.IsChecked = FidoLogonApi.AutoSyncMetadata;
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
    }

    private async void OnSyncClicked(object sender, RoutedEventArgs e)
    {
        SyncButton.IsEnabled = false;
        StatusText.Text = "Downloading the FIDO metadata…";
        try
        {
            using HttpClient client = KeyModelPolicy.CreateHttpClient();
            MetadataSyncResult result = await _policy.SyncAsync(client);
            StatusText.Text = result.Import is null
                ? $"Already up to date (BLOB #{result.Number})."
                : $"Downloaded BLOB #{result.Number}.";
            if (result.Import is { Blocked.Count: > 0 } import)
            {
                MessageBox.Show(this,
                    $"Now revoked or compromised, enrollment refuses them:\n{string.Join("\n", import.Blocked)}",
                    "FidoLogon", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex) when (ex is MetadataException or FidoLogonException or IOException or UnauthorizedAccessException)
        {
            StatusText.Text = "";
            ShowError(ex.Message);
        }
        finally
        {
            SyncButton.IsEnabled = true;
        }
        LoadMetadata();
        ReloadAllowed();
    }

    private void OnCertifiedClicked(object sender, RoutedEventArgs e)
    {
        bool allow = CertifiedCheckBox.IsChecked == true;
        try
        {
            _policy.SetAllowCertifiedModels(allow);
            StatusText.Text = allow
                ? $"Every certified model can be enrolled ({FidoLogonApi.CountCertifiedModels()} models)."
                : "Only the allowed list counts.";
        }
        catch (Exception ex) when (ex is MetadataException or FidoLogonException)
        {
            ShowError(ex.Message);
        }
        ReloadOptions();
    }

    private void OnAutoSyncClicked(object sender, RoutedEventArgs e)
    {
        try
        {
            FidoLogonApi.AutoSyncMetadata = AutoSyncCheckBox.IsChecked == true;
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
        ReloadOptions();
    }

    private void LoadMetadata()
    {
        try
        {
            _metadata = _policy.LoadMetadata();
            MetadataInfo.Text = _metadata is null
                ? "No FIDO Metadata Service BLOB imported: synchronize, or download it from https://mds3.fidoalliance.org/ and import it."
                : $"Imported metadata: BLOB #{_metadata.Number} ({_metadata.Entries.Count} FIDO2 models), " +
                  $"next update {_metadata.NextUpdate:yyyy-MM-dd}." +
                  (_metadata.NextUpdate < DateOnly.FromDateTime(DateTime.Today) ? " A newer BLOB is available." : "");
        }
        catch (MetadataException ex)
        {
            _metadata = null;
            MetadataInfo.Text = $"The imported metadata is invalid: {ex.Message}";
        }
        ApplySearch();
    }

    private void ReloadAllowed()
    {
        try
        {
            AllowedGrid.ItemsSource = FidoLogonApi.ListAllowedModels();
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
        RemoveButton.IsEnabled = false;
    }

    private void ApplySearch()
    {
        string text = SearchBox.Text.Trim();
        MetadataGrid.ItemsSource = _metadata?.Entries
            .Where(e => text.Length == 0 || e.Description.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                        e.Aaguid.StartsWith(text, StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.Description, StringComparer.OrdinalIgnoreCase)
            .ToList();
        AllowButton.IsEnabled = false;
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e) => ApplySearch();

    private void OnAllowedSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        RemoveButton.IsEnabled = AllowedGrid.SelectedItem is not null;

    private void OnMetadataSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        AllowButton.IsEnabled = MetadataGrid.SelectedItem is MetadataEntry { IsBlocked: false };

    private void OnImportClicked(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "FIDO Metadata Service BLOB",
            Filter = "MDS3 BLOB (*.jwt;*.txt)|*.jwt;*.txt|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }
        try
        {
            MetadataImportResult result = _policy.Import(dialog.FileName);
            string message = $"Imported BLOB #{result.Number} ({result.EntryCount} FIDO2 models).";
            if (result.Blocked.Count > 0)
            {
                message += $"\n\nNow revoked or compromised, enrollment refuses them:\n{string.Join("\n", result.Blocked)}";
            }
            if (result.Missing.Count > 0)
            {
                message += $"\n\nNo longer described (kept unchanged):\n{string.Join("\n", result.Missing)}";
            }
            MessageBox.Show(this, message, "FidoLogon", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) when (ex is MetadataException or FidoLogonException or IOException or UnauthorizedAccessException)
        {
            ShowError(ex.Message);
        }
        LoadMetadata();
        ReloadAllowed();
    }

    private void OnAllowClicked(object sender, RoutedEventArgs e)
    {
        if (MetadataGrid.SelectedItem is not MetadataEntry entry)
        {
            return;
        }
        try
        {
            _policy.Allow(entry.Aaguid);
            StatusText.Text = $"{entry.Description} allowed.";
        }
        catch (Exception ex) when (ex is MetadataException or FidoLogonException)
        {
            ShowError(ex.Message);
        }
        ReloadAllowed();
    }

    private void OnRemoveClicked(object sender, RoutedEventArgs e)
    {
        if (AllowedGrid.SelectedItem is not AllowedKeyModel model)
        {
            return;
        }
        try
        {
            KeyModelPolicy.Remove(model.Aaguid);
            StatusText.Text = $"{model.Description} removed.";
        }
        catch (FidoLogonException ex)
        {
            ShowError(ex.Message);
        }
        ReloadAllowed();
    }

    private void ShowError(string message) =>
        MessageBox.Show(this, message, "FidoLogon", MessageBoxButton.OK, MessageBoxImage.Error);
}
