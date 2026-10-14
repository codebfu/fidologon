using System.Windows;

namespace FidoLogon.Config;

/// <summary>Non-modal prompt shown while the security key waits for a touch.</summary>
public partial class TouchPromptWindow : Window
{
    public TouchPromptWindow()
    {
        InitializeComponent();
    }

    /// <summary>Shows (or updates) the prompt for touch <paramref name="touch"/> of <paramref name="total"/>.</summary>
    public void ShowTouch(int touch, int total, string detail)
    {
        StepText.Text = total > 1 ? $"Touch {touch} of {total}" : "";
        StepText.Visibility = total > 1 ? Visibility.Visible : Visibility.Collapsed;
        DetailText.Text = detail;
        if (!IsVisible)
        {
            Show();
        }
        Activate();
    }
}
