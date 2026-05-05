<#
.SYNOPSIS
    SOC Operations Dashboard - WPF/XAML edition with tabbed views.

.DESCRIPTION
    Modern WPF rendering of the SOC analyst console with smooth animations,
    consistent dark theming, hardware-accelerated compositing, rounded panels,
    and draggable splitters between dashboard panes.

    Top-level tabs:
        Dashboard       - KPI tiles + Newest KEVs / Feed Health / Critical CVEs
        MITRE ATT&CK    - sub-tabs: Tactics / Techniques / Sub-techniques /
                          Groups / Software / Mitigations
        CVEs            - last-30d NVD CVE cache, filterable
        KEVs            - CISA Known-Exploited catalog, filterable
        IoC Search      - global keyword search across all tables above

    Reads from %USERPROFILE%\SecIntel\secintel.db, the same DB the WinForms
    version uses. The header bar's Update buttons (KEV / CVE / EPSS / MITRE)
    spawn child PowerShell windows that auto-close after a 5-second countdown.
    Refresh View reloads the data for whichever tab is currently active.

    Layout: this script lives at the project root and is the only entry
    point the analyst launches. All implementation modules live in the
    sibling Modules\ folder and are dot-sourced or invoked from here.

    EPSS prioritization: when Update-EpssFeed.ps1 has been run, the CVEs
    tab and the Critical CVEs panel sort by CvssScore * EpssPercentile
    (i.e. "how bad x how likely") rather than CVSS alone, so high-risk
    CVEs surface first regardless of publish date.

.PARAMETER NoLoad
    Skip the initial data refresh on load. Useful for theme tweaking when
    you don't want to wait on SQL.

.NOTES
    PowerShell 5.1+. WPF ships with .NET Framework on every Windows install
    since Vista. No admin rights, no extra runtimes.
#>

[CmdletBinding()]
param(
    [switch]$NoLoad
)

$ErrorActionPreference = 'Stop'

# ---------- Shared schema / paths / dependency bootstrap ----------
# All implementation modules live in .\Modules\ alongside this single
# entry-point script. SocDashboard.ps1 is the only file the analyst
# launches directly; everything else is dot-sourced or invoked from here.
$script:ModulesDir = Join-Path $PSScriptRoot 'Modules'
. (Join-Path $script:ModulesDir 'SecIntel.Schema.ps1')
Ensure-PSSQLite
Initialize-SecIntelSchema

# ---------- WPF assemblies ----------
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml

# ============================================================
# XAML
# ============================================================
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SOC Operations Dashboard"
        Height="860" Width="1320"
        MinHeight="700" MinWidth="1200"
        Background="#0D1117"
        WindowStartupLocation="CenterScreen"
        FontFamily="Consolas"
        TextOptions.TextFormattingMode="Ideal"
        UseLayoutRounding="True"
        Opacity="0">
    <Window.Resources>
        <!-- ===== Brushes ===== -->
        <SolidColorBrush x:Key="BgBrush"        Color="#0D1117"/>
        <SolidColorBrush x:Key="BgAltBrush"     Color="#161B22"/>
        <SolidColorBrush x:Key="BgPanelBrush"   Color="#1C2128"/>
        <SolidColorBrush x:Key="BgPanelHover"   Color="#22304A"/>
        <SolidColorBrush x:Key="BorderBrush"    Color="#30363D"/>
        <SolidColorBrush x:Key="FgBrush"        Color="#E6EDF3"/>
        <SolidColorBrush x:Key="FgDimBrush"     Color="#8B949E"/>
        <SolidColorBrush x:Key="AccentBrush"    Color="#58A6FF"/>
        <SolidColorBrush x:Key="AccentAltBrush" Color="#39D353"/>
        <SolidColorBrush x:Key="WarnBrush"      Color="#FFA657"/>
        <SolidColorBrush x:Key="DangerBrush"    Color="#FF6B6B"/>
        <SolidColorBrush x:Key="SelBgBrush"     Color="#1F6FEB"/>

        <!-- ===== Section header (above each grid panel) ===== -->
        <Style x:Key="SectionHeader" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource AccentBrush}"/>
            <Setter Property="Background" Value="{StaticResource BgAltBrush}"/>
            <Setter Property="FontSize"   Value="11"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Padding"    Value="14,9,14,9"/>
        </Style>

        <!-- ===== Search prompt ("SEARCH >") ===== -->
        <Style x:Key="SearchPrompt" TargetType="TextBlock">
            <Setter Property="Foreground"        Value="{StaticResource AccentBrush}"/>
            <Setter Property="FontWeight"        Value="Bold"/>
            <Setter Property="FontSize"          Value="11"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="Margin"            Value="0,0,12,0"/>
        </Style>

        <!-- ===== Count label (right of search bar) ===== -->
        <Style x:Key="CountLabel" TargetType="TextBlock">
            <Setter Property="Foreground"        Value="{StaticResource FgDimBrush}"/>
            <Setter Property="FontSize"          Value="10"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="Margin"            Value="14,0,0,0"/>
            <Setter Property="MinWidth"          Value="80"/>
        </Style>

        <!-- ===== KPI Tile ===== -->
        <Style x:Key="KpiTile" TargetType="Border">
            <Setter Property="Background"      Value="{StaticResource BgPanelBrush}"/>
            <Setter Property="BorderBrush"     Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius"    Value="6"/>
            <Setter Property="Padding"         Value="16,14,16,14"/>
            <Setter Property="Margin"          Value="6,0,6,0"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="KpiCaption" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource FgDimBrush}"/>
            <Setter Property="FontSize"   Value="10"/>
            <Setter Property="FontWeight" Value="Bold"/>
        </Style>
        <Style x:Key="KpiValue" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource AccentBrush}"/>
            <Setter Property="FontSize"   Value="34"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Margin"     Value="0,8,0,2"/>
        </Style>
        <Style x:Key="KpiSub" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource FgDimBrush}"/>
            <Setter Property="FontSize"   Value="10"/>
        </Style>

        <!-- ===== Dark Button ===== -->
        <Style x:Key="DarkButton" TargetType="Button">
            <Setter Property="Foreground"      Value="{StaticResource AccentBrush}"/>
            <Setter Property="Background"      Value="{StaticResource BgPanelBrush}"/>
            <Setter Property="BorderBrush"     Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding"         Value="14,6,14,6"/>
            <Setter Property="Margin"          Value="0,0,8,0"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="FontSize"        Value="11"/>
            <Setter Property="MinWidth"        Value="92"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Border"
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background"  Value="{StaticResource BgPanelHover}"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="{StaticResource SelBgBrush}"/>
                                <Setter Property="Foreground" Value="White"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ===== TextBox ===== -->
        <Style TargetType="TextBox">
            <Setter Property="Background"               Value="{StaticResource BgPanelBrush}"/>
            <Setter Property="Foreground"               Value="{StaticResource FgBrush}"/>
            <Setter Property="BorderBrush"              Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness"          Value="1"/>
            <Setter Property="Padding"                  Value="8,5,8,5"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="CaretBrush"               Value="{StaticResource AccentBrush}"/>
            <Setter Property="SelectionBrush"           Value="{StaticResource SelBgBrush}"/>
            <Setter Property="FontSize"                 Value="11"/>
        </Style>

        <!-- ===== DataGrid + cells + headers ===== -->
        <Style TargetType="DataGrid">
            <Setter Property="Background"               Value="{StaticResource BgBrush}"/>
            <Setter Property="Foreground"               Value="{StaticResource FgBrush}"/>
            <Setter Property="BorderThickness"          Value="0"/>
            <Setter Property="GridLinesVisibility"      Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="RowBackground"            Value="{StaticResource BgBrush}"/>
            <Setter Property="AlternatingRowBackground" Value="#13181F"/>
            <Setter Property="HeadersVisibility"        Value="Column"/>
            <Setter Property="AutoGenerateColumns"      Value="True"/>
            <Setter Property="IsReadOnly"               Value="True"/>
            <Setter Property="SelectionMode"            Value="Single"/>
            <Setter Property="SelectionUnit"            Value="FullRow"/>
            <Setter Property="CanUserResizeRows"        Value="False"/>
            <Setter Property="CanUserAddRows"           Value="False"/>
            <Setter Property="CanUserDeleteRows"        Value="False"/>
            <Setter Property="RowHeaderWidth"           Value="0"/>
            <Setter Property="FontSize"                 Value="11"/>
            <Setter Property="EnableRowVirtualization"  Value="True"/>
        </Style>

        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background"      Value="{StaticResource BgPanelBrush}"/>
            <Setter Property="Foreground"      Value="{StaticResource AccentBrush}"/>
            <Setter Property="FontWeight"      Value="Bold"/>
            <Setter Property="FontSize"        Value="11"/>
            <Setter Property="Padding"         Value="10,8,10,8"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="BorderBrush"     Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>

        <Style TargetType="DataGridRow">
            <Setter Property="Foreground" Value="{StaticResource FgBrush}"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="{StaticResource BgPanelBrush}"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="DataGridCell">
            <Setter Property="Background"  Value="Transparent"/>
            <Setter Property="Foreground"  Value="{StaticResource FgBrush}"/>
            <Setter Property="BorderBrush" Value="Transparent"/>
            <Setter Property="Padding"     Value="10,6,10,6"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="{StaticResource SelBgBrush}"/>
                    <Setter Property="Foreground" Value="White"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- ===== GridSplitter ===== -->
        <Style TargetType="GridSplitter">
            <Setter Property="Background"   Value="{StaticResource BorderBrush}"/>
            <Setter Property="ShowsPreview" Value="False"/>
            <Setter Property="Focusable"    Value="False"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="{StaticResource AccentBrush}"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- ===== ListBox / ItemsControl (templates list, project columns, etc) ===== -->
        <Style TargetType="ListBox">
            <Setter Property="Background"      Value="{StaticResource BgBrush}"/>
            <Setter Property="Foreground"      Value="{StaticResource FgBrush}"/>
            <Setter Property="BorderBrush"     Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="FontSize"        Value="12"/>
        </Style>

        <Style TargetType="ListBoxItem">
            <Setter Property="Background"      Value="Transparent"/>
            <Setter Property="Foreground"      Value="{StaticResource FgBrush}"/>
            <Setter Property="Padding"         Value="12,6,12,6"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ListBoxItem">
                        <Border x:Name="Border"
                                Background="{TemplateBinding Background}"
                                BorderBrush="Transparent"
                                BorderThickness="0,0,0,1"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background"  Value="{StaticResource BgPanelBrush}"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
                            </Trigger>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="{StaticResource SelBgBrush}"/>
                                <Setter Property="Foreground" Value="White"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ===== ScrollViewer (used inside Tabs / sub-tabs) ===== -->
        <Style TargetType="ScrollViewer">
            <Setter Property="Background" Value="{StaticResource BgBrush}"/>
        </Style>

        <!-- ===== ItemsControl (project column checkbox list) ===== -->
        <Style TargetType="ItemsControl">
            <Setter Property="Background" Value="{StaticResource BgBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource FgBrush}"/>
        </Style>

        <!-- ===== TabControl ===== -->
        <Style TargetType="TabControl">
            <Setter Property="Background"      Value="{StaticResource BgBrush}"/>
            <Setter Property="BorderBrush"     Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding"         Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabControl">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <Border Grid.Row="0" Background="{StaticResource BgAltBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1">
                                <TabPanel x:Name="HeaderPanel" IsItemsHost="True"
                                          Background="Transparent" Margin="6,4,0,0"/>
                            </Border>
                            <Border Grid.Row="1" Background="{StaticResource BgBrush}">
                                <ContentPresenter ContentSource="SelectedContent"/>
                            </Border>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ===== TabItem ===== -->
        <Style TargetType="TabItem">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{StaticResource FgDimBrush}"/>
            <Setter Property="Padding"    Value="16,8,16,8"/>
            <Setter Property="FontSize"   Value="11"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Cursor"     Value="Hand"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border x:Name="Border"
                                Background="{TemplateBinding Background}"
                                BorderBrush="Transparent"
                                BorderThickness="0,0,0,2"
                                Padding="{TemplateBinding Padding}"
                                Margin="0,0,2,0">
                            <ContentPresenter ContentSource="Header"
                                              HorizontalAlignment="Center"
                                              VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="Background"  Value="{StaticResource BgPanelBrush}"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                                <Setter Property="Foreground" Value="{StaticResource AccentBrush}"/>
                            </Trigger>
                            <MultiTrigger>
                                <MultiTrigger.Conditions>
                                    <Condition Property="IsSelected"  Value="False"/>
                                    <Condition Property="IsMouseOver" Value="True"/>
                                </MultiTrigger.Conditions>
                                <Setter Property="Foreground" Value="{StaticResource FgBrush}"/>
                            </MultiTrigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <!-- ===== Window-level fade-in animation on load ===== -->
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard>
                <Storyboard>
                    <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                     From="0" To="1" Duration="0:0:0.30"/>
                </Storyboard>
            </BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>  <!-- Persistent header -->
            <RowDefinition Height="*"/>     <!-- Tab content       -->
        </Grid.RowDefinitions>

        <!-- ===== Persistent header strip ===== -->
        <Border Grid.Row="0"
                Background="{StaticResource BgAltBrush}"
                BorderBrush="{StaticResource BorderBrush}"
                BorderThickness="0,0,0,1">
            <Grid Margin="16,12,16,12">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <!-- Row 1: title + Refresh View -->
                <TextBlock Grid.Row="0" Grid.Column="0"
                           Text="SOC OPERATIONS DASHBOARD"
                           Foreground="{StaticResource AccentBrush}"
                           FontSize="16" FontWeight="Bold"
                           VerticalAlignment="Center"/>
                <StackPanel Grid.Row="0" Grid.Column="1"
                            Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock x:Name="LastRefreshLbl"
                               Foreground="{StaticResource FgDimBrush}"
                               FontSize="11" VerticalAlignment="Center"
                               Margin="0,0,14,0"/>
                    <Button x:Name="RefreshBtn"
                            Content="Refresh View"
                            Style="{StaticResource DarkButton}"
                            MinWidth="120"/>
                </StackPanel>

                <!-- Row 2: feed-update buttons + status -->
                <StackPanel Grid.Row="1" Grid.Column="0"
                            Orientation="Horizontal" Margin="0,12,0,0">
                    <Button x:Name="BtnUpdateKev"   Content="Update KEV"   Style="{StaticResource DarkButton}"/>
                    <Button x:Name="BtnUpdateCve"   Content="Update CVE"   Style="{StaticResource DarkButton}"/>
                    <Button x:Name="BtnUpdateEpss"  Content="Update EPSS"  Style="{StaticResource DarkButton}"/>
                    <Button x:Name="BtnUpdateMitre" Content="Update MITRE" Style="{StaticResource DarkButton}" MinWidth="130"/>
                    <TextBlock x:Name="JobStatusLbl"
                               Margin="14,0,0,0" VerticalAlignment="Center"
                               Foreground="{StaticResource AccentAltBrush}"
                               FontSize="11"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- ===== Top-level TabControl ===== -->
        <TabControl Grid.Row="1" x:Name="MainTabs">

            <!-- ============= Dashboard tab ============= -->
            <TabItem Header="Dashboard" x:Name="DashboardTab">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <!-- KPI strip -->
                    <UniformGrid Grid.Row="0" Rows="1" Columns="4" Margin="10,12,10,4">
                        <Border Style="{StaticResource KpiTile}">
                            <StackPanel>
                                <TextBlock Text="FEED STATUS" Style="{StaticResource KpiCaption}"/>
                                <TextBlock x:Name="KpiFeedValue" Text="--" Style="{StaticResource KpiValue}"/>
                                <TextBlock x:Name="KpiFeedSub"   Text=""   Style="{StaticResource KpiSub}"/>
                            </StackPanel>
                        </Border>
                        <Border Style="{StaticResource KpiTile}">
                            <StackPanel>
                                <TextBlock Text="KEV CATALOG (TOTAL)" Style="{StaticResource KpiCaption}"/>
                                <TextBlock x:Name="KpiKevValue" Text="--" Style="{StaticResource KpiValue}"/>
                                <TextBlock x:Name="KpiKevSub"   Text=""   Style="{StaticResource KpiSub}"/>
                            </StackPanel>
                        </Border>
                        <Border Style="{StaticResource KpiTile}">
                            <StackPanel>
                                <TextBlock Text="CRITICAL CVES (CACHED)" Style="{StaticResource KpiCaption}"/>
                                <TextBlock x:Name="KpiCveValue" Text="--" Style="{StaticResource KpiValue}"/>
                                <TextBlock x:Name="KpiCveSub"   Text=""   Style="{StaticResource KpiSub}"/>
                            </StackPanel>
                        </Border>
                        <Border Style="{StaticResource KpiTile}">
                            <StackPanel>
                                <TextBlock Text="KEVS - RANSOMWARE" Style="{StaticResource KpiCaption}"/>
                                <TextBlock x:Name="KpiRanValue" Text="--" Style="{StaticResource KpiValue}"/>
                                <TextBlock x:Name="KpiRanSub"   Text=""   Style="{StaticResource KpiSub}"/>
                            </StackPanel>
                        </Border>
                    </UniformGrid>

                    <!-- Body with splitters -->
                    <Grid Grid.Row="1" Margin="10,8,10,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"  MinWidth="240"/>
                            <ColumnDefinition Width="6"/>
                            <ColumnDefinition Width="*"  MinWidth="240"/>
                        </Grid.ColumnDefinitions>

                        <Border Grid.Column="0"
                                Background="{StaticResource BgPanelBrush}"
                                BorderBrush="{StaticResource BorderBrush}"
                                BorderThickness="1" CornerRadius="6">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="*"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="NEWEST KEVS" Style="{StaticResource SectionHeader}"/>
                                <DataGrid Grid.Row="1" x:Name="NewKevGrid"/>
                            </Grid>
                        </Border>

                        <GridSplitter Grid.Column="1" Width="6"
                                      HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                                      ResizeBehavior="PreviousAndNext" ResizeDirection="Columns" Cursor="SizeWE"/>

                        <Grid Grid.Column="2">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*"  MinHeight="120"/>
                                <RowDefinition Height="6"/>
                                <RowDefinition Height="2*" MinHeight="120"/>
                            </Grid.RowDefinitions>

                            <Border Grid.Row="0"
                                    Background="{StaticResource BgPanelBrush}"
                                    BorderBrush="{StaticResource BorderBrush}"
                                    BorderThickness="1" CornerRadius="6">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Grid.Row="0" Text="FEED HEALTH" Style="{StaticResource SectionHeader}"/>
                                    <DataGrid Grid.Row="1" x:Name="FeedGrid"/>
                                </Grid>
                            </Border>

                            <GridSplitter Grid.Row="1" Height="6"
                                          HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                                          ResizeBehavior="PreviousAndNext" ResizeDirection="Rows" Cursor="SizeNS"/>

                            <Border Grid.Row="2"
                                    Background="{StaticResource BgPanelBrush}"
                                    BorderBrush="{StaticResource BorderBrush}"
                                    BorderThickness="1" CornerRadius="6">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Grid.Row="0" Text="CRITICAL CVES (CVSS &gt;= 9.0)" Style="{StaticResource SectionHeader}"/>
                                    <DataGrid Grid.Row="1" x:Name="CritCveGrid"/>
                                </Grid>
                            </Border>
                        </Grid>
                    </Grid>
                </Grid>
            </TabItem>

            <!-- ============= MITRE ATT&CK tab (with sub-tabs) ============= -->
            <TabItem Header="MITRE ATT&amp;CK" x:Name="MitreTab">
                <TabControl x:Name="MitreSubTabs" Margin="0">

                    <TabItem Header="Tactics" x:Name="TacticsTab">
                        <DockPanel LastChildFill="True">
                            <Border DockPanel.Dock="Top"
                                    Background="{StaticResource BgAltBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                    Padding="12,8,12,8">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Grid.Column="0" Text="SEARCH &gt;" Style="{StaticResource SearchPrompt}"/>
                                    <TextBox   Grid.Column="1" x:Name="TacticsSearchTxt" Margin="0,0,8,0"/>
                                    <Button    Grid.Column="2" x:Name="TacticsFilterBtn" Content="Filter" Style="{StaticResource DarkButton}"/>
                                    <Button    Grid.Column="3" x:Name="TacticsClearBtn"  Content="Clear"  Style="{StaticResource DarkButton}"/>
                                    <TextBlock Grid.Column="4" x:Name="TacticsCountLbl"  Style="{StaticResource CountLabel}"/>
                                </Grid>
                            </Border>
                            <DataGrid x:Name="TacticsGrid"/>
                        </DockPanel>
                    </TabItem>

                    <TabItem Header="Techniques" x:Name="TechniquesTab">
                        <DockPanel LastChildFill="True">
                            <Border DockPanel.Dock="Top"
                                    Background="{StaticResource BgAltBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                    Padding="12,8,12,8">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Grid.Column="0" Text="SEARCH &gt;" Style="{StaticResource SearchPrompt}"/>
                                    <TextBox   Grid.Column="1" x:Name="TechniquesSearchTxt" Margin="0,0,8,0"/>
                                    <Button    Grid.Column="2" x:Name="TechniquesFilterBtn" Content="Filter" Style="{StaticResource DarkButton}"/>
                                    <Button    Grid.Column="3" x:Name="TechniquesClearBtn"  Content="Clear"  Style="{StaticResource DarkButton}"/>
                                    <TextBlock Grid.Column="4" x:Name="TechniquesCountLbl"  Style="{StaticResource CountLabel}"/>
                                </Grid>
                            </Border>
                            <DataGrid x:Name="TechniquesGrid"/>
                        </DockPanel>
                    </TabItem>

                    <TabItem Header="Sub-techniques" x:Name="SubTechniquesTab">
                        <DockPanel LastChildFill="True">
                            <Border DockPanel.Dock="Top"
                                    Background="{StaticResource BgAltBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                    Padding="12,8,12,8">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Grid.Column="0" Text="SEARCH &gt;" Style="{StaticResource SearchPrompt}"/>
                                    <TextBox   Grid.Column="1" x:Name="SubTechniquesSearchTxt" Margin="0,0,8,0"/>
                                    <Button    Grid.Column="2" x:Name="SubTechniquesFilterBtn" Content="Filter" Style="{StaticResource DarkButton}"/>
                                    <Button    Grid.Column="3" x:Name="SubTechniquesClearBtn"  Content="Clear"  Style="{StaticResource DarkButton}"/>
                                    <TextBlock Grid.Column="4" x:Name="SubTechniquesCountLbl"  Style="{StaticResource CountLabel}"/>
                                </Grid>
                            </Border>
                            <DataGrid x:Name="SubTechniquesGrid"/>
                        </DockPanel>
                    </TabItem>

                    <TabItem Header="Groups" x:Name="GroupsTab">
                        <DockPanel LastChildFill="True">
                            <Border DockPanel.Dock="Top"
                                    Background="{StaticResource BgAltBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                    Padding="12,8,12,8">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Grid.Column="0" Text="SEARCH &gt;" Style="{StaticResource SearchPrompt}"/>
                                    <TextBox   Grid.Column="1" x:Name="GroupsSearchTxt" Margin="0,0,8,0"/>
                                    <Button    Grid.Column="2" x:Name="GroupsFilterBtn" Content="Filter" Style="{StaticResource DarkButton}"/>
                                    <Button    Grid.Column="3" x:Name="GroupsClearBtn"  Content="Clear"  Style="{StaticResource DarkButton}"/>
                                    <TextBlock Grid.Column="4" x:Name="GroupsCountLbl"  Style="{StaticResource CountLabel}"/>
                                </Grid>
                            </Border>
                            <DataGrid x:Name="GroupsGrid"/>
                        </DockPanel>
                    </TabItem>

                    <TabItem Header="Software" x:Name="SoftwareTab">
                        <DockPanel LastChildFill="True">
                            <Border DockPanel.Dock="Top"
                                    Background="{StaticResource BgAltBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                    Padding="12,8,12,8">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Grid.Column="0" Text="SEARCH &gt;" Style="{StaticResource SearchPrompt}"/>
                                    <TextBox   Grid.Column="1" x:Name="SoftwareSearchTxt" Margin="0,0,8,0"/>
                                    <Button    Grid.Column="2" x:Name="SoftwareFilterBtn" Content="Filter" Style="{StaticResource DarkButton}"/>
                                    <Button    Grid.Column="3" x:Name="SoftwareClearBtn"  Content="Clear"  Style="{StaticResource DarkButton}"/>
                                    <TextBlock Grid.Column="4" x:Name="SoftwareCountLbl"  Style="{StaticResource CountLabel}"/>
                                </Grid>
                            </Border>
                            <DataGrid x:Name="SoftwareGrid"/>
                        </DockPanel>
                    </TabItem>

                    <TabItem Header="Mitigations" x:Name="MitigationsTab">
                        <DockPanel LastChildFill="True">
                            <Border DockPanel.Dock="Top"
                                    Background="{StaticResource BgAltBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                    Padding="12,8,12,8">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Grid.Column="0" Text="SEARCH &gt;" Style="{StaticResource SearchPrompt}"/>
                                    <TextBox   Grid.Column="1" x:Name="MitigationsSearchTxt" Margin="0,0,8,0"/>
                                    <Button    Grid.Column="2" x:Name="MitigationsFilterBtn" Content="Filter" Style="{StaticResource DarkButton}"/>
                                    <Button    Grid.Column="3" x:Name="MitigationsClearBtn"  Content="Clear"  Style="{StaticResource DarkButton}"/>
                                    <TextBlock Grid.Column="4" x:Name="MitigationsCountLbl"  Style="{StaticResource CountLabel}"/>
                                </Grid>
                            </Border>
                            <DataGrid x:Name="MitigationsGrid"/>
                        </DockPanel>
                    </TabItem>

                </TabControl>
            </TabItem>

            <!-- ============= KQL Builder tab ============= -->
            <TabItem Header="KQL Builder" x:Name="KqlTab">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"   MinHeight="240"/>
                        <RowDefinition Height="6"/>
                        <RowDefinition Height="240" MinHeight="120"/>
                    </Grid.RowDefinitions>

                    <!-- Source strip: table, time range, action buttons -->
                    <Border Grid.Row="0"
                            Background="{StaticResource BgAltBrush}"
                            BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                            Padding="12,10,12,10">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="240"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="160"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Grid.Column="0" Text="TABLE:" Style="{StaticResource SearchPrompt}"/>
                            <ComboBox  Grid.Column="1" x:Name="KqlTableCombo" IsEditable="True"/>
                            <TextBlock Grid.Column="2" Text="TIME:" Style="{StaticResource SearchPrompt}" Margin="20,0,12,0"/>
                            <ComboBox  Grid.Column="3" x:Name="KqlTimeCombo"/>
                            <TextBox   Grid.Column="4" x:Name="KqlCustomTimeTxt"
                                       Visibility="Collapsed" Margin="12,0,0,0"
                                       ToolTip="Custom KQL time predicate, e.g. between(datetime(2024-01-01) .. datetime(2024-01-31))"/>
                            <Button    Grid.Column="5" x:Name="KqlBuildBtn"  Content="Build Query" Style="{StaticResource DarkButton}" MinWidth="110" Margin="20,0,0,0"/>
                            <Button    Grid.Column="6" x:Name="KqlCopyBtn"   Content="Copy KQL"    Style="{StaticResource DarkButton}" MinWidth="90"/>
                            <Button    Grid.Column="7" x:Name="KqlResetBtn"  Content="Reset"       Style="{StaticResource DarkButton}" MinWidth="80"/>
                        </Grid>
                    </Border>

                    <!-- Builder sub-tabs -->
                    <TabControl Grid.Row="1" x:Name="KqlSubTabs">

                        <!-- ===== Filters ===== -->
                        <TabItem Header="Filters">
                            <DockPanel LastChildFill="True">
                                <Border DockPanel.Dock="Top"
                                        Background="{StaticResource BgAltBrush}"
                                        BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                        Padding="12,8,12,8">
                                    <StackPanel Orientation="Horizontal">
                                        <Button x:Name="KqlAddFilterBtn"    Content="+ Add Filter" Style="{StaticResource DarkButton}"/>
                                        <Button x:Name="KqlClearFiltersBtn" Content="Clear All"    Style="{StaticResource DarkButton}"/>
                                        <TextBlock Foreground="{StaticResource FgDimBrush}"
                                                   VerticalAlignment="Center" Margin="14,0,0,0" FontSize="10">
                                            Predicates ranked by cost (cheapest first): == &lt; has &lt; startswith/endswith &lt; contains &lt; matches regex. Filter early. Use != / !contains / !in for exclusions.
                                        </TextBlock>
                                    </StackPanel>
                                </Border>
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <StackPanel x:Name="KqlFiltersStack" Margin="14"/>
                                </ScrollViewer>
                            </DockPanel>
                        </TabItem>

                        <!-- ===== Parse / Extend ===== -->
                        <TabItem Header="Parse &amp; Extend">
                            <DockPanel LastChildFill="True">
                                <Border DockPanel.Dock="Top"
                                        Background="{StaticResource BgAltBrush}"
                                        BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                        Padding="12,8,12,8">
                                    <StackPanel Orientation="Horizontal">
                                        <Button x:Name="KqlAddExtendBtn"   Content="+ Add Extend" Style="{StaticResource DarkButton}"/>
                                        <Button x:Name="KqlClearExtendBtn" Content="Clear All"    Style="{StaticResource DarkButton}"/>
                                        <TextBlock Foreground="{StaticResource FgDimBrush}"
                                                   VerticalAlignment="Center" Margin="14,0,0,0" FontSize="10">
                                            Computed columns. Examples: Hour=hourofday(TimeGenerated), Domain=tostring(split(Account,'\\')[0]), AppData=parse_json(EventData)
                                        </TextBlock>
                                    </StackPanel>
                                </Border>
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <StackPanel x:Name="KqlExtendStack" Margin="14"/>
                                </ScrollViewer>
                            </DockPanel>
                        </TabItem>

                        <!-- ===== Project ===== -->
                        <TabItem Header="Project">
                            <DockPanel LastChildFill="True">
                                <Border DockPanel.Dock="Top"
                                        Background="{StaticResource BgAltBrush}"
                                        BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                        Padding="12,8,12,8">
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock Text="MODE:" Style="{StaticResource SearchPrompt}"/>
                                        <RadioButton x:Name="KqlProjectMode_Project"     Content="project (keep checked)"
                                                     GroupName="KqlProjMode" IsChecked="True"
                                                     Foreground="{StaticResource FgBrush}"
                                                     VerticalAlignment="Center" Margin="0,0,16,0"/>
                                        <RadioButton x:Name="KqlProjectMode_ProjectAway" Content="project-away (drop checked)"
                                                     GroupName="KqlProjMode"
                                                     Foreground="{StaticResource FgBrush}"
                                                     VerticalAlignment="Center"/>
                                        <Button x:Name="KqlProjectAllBtn"  Content="Select All"  Style="{StaticResource DarkButton}" Margin="20,0,0,0"/>
                                        <Button x:Name="KqlProjectNoneBtn" Content="Select None" Style="{StaticResource DarkButton}"/>
                                    </StackPanel>
                                </Border>
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <ItemsControl x:Name="KqlProjectList" Background="{StaticResource BgBrush}"/>
                                </ScrollViewer>
                            </DockPanel>
                        </TabItem>

                        <!-- ===== Aggregate ===== -->
                        <TabItem Header="Aggregate">
                            <DockPanel LastChildFill="True">
                                <Border DockPanel.Dock="Top"
                                        Background="{StaticResource BgAltBrush}"
                                        BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                        Padding="12,8,12,8">
                                    <StackPanel Orientation="Horizontal">
                                        <Button x:Name="KqlAddAggBtn"   Content="+ Add Aggregation" Style="{StaticResource DarkButton}"/>
                                        <Button x:Name="KqlClearAggBtn" Content="Clear All"          Style="{StaticResource DarkButton}"/>
                                        <TextBlock Text="BIN TIME:" Style="{StaticResource SearchPrompt}" Margin="20,0,8,0"/>
                                        <ComboBox  x:Name="KqlBinTimeCombo" Width="120"/>
                                        <TextBlock Text="GROUP BY:" Style="{StaticResource SearchPrompt}" Margin="20,0,8,0"/>
                                        <TextBox   x:Name="KqlGroupByTxt" Width="320"
                                                   ToolTip="Comma-separated column list, e.g. Account, Computer"/>
                                    </StackPanel>
                                </Border>
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <StackPanel x:Name="KqlAggStack" Margin="14"/>
                                </ScrollViewer>
                            </DockPanel>
                        </TabItem>

                        <!-- ===== Order / Limit ===== -->
                        <TabItem Header="Order &amp; Limit">
                            <ScrollViewer>
                                <StackPanel Margin="20,16,20,16">
                                    <TextBlock Text="ORDER BY" Style="{StaticResource SectionHeader}"
                                               Background="Transparent" Padding="0,0,0,8"/>
                                    <Grid Margin="0,0,0,20">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="320"/>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="160"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBlock Grid.Column="0" Text="Column:" Foreground="{StaticResource FgBrush}"
                                                   VerticalAlignment="Center" Margin="0,0,8,0"/>
                                        <ComboBox  Grid.Column="1" x:Name="KqlOrderColCombo" IsEditable="True"/>
                                        <TextBlock Grid.Column="2" Text="Direction:" Foreground="{StaticResource FgBrush}"
                                                   VerticalAlignment="Center" Margin="20,0,8,0"/>
                                        <ComboBox  Grid.Column="3" x:Name="KqlOrderDirCombo"/>
                                    </Grid>

                                    <TextBlock Text="TAKE / TOP" Style="{StaticResource SectionHeader}"
                                               Background="Transparent" Padding="0,0,0,8"/>
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="160"/>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="200"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBlock Grid.Column="0" Text="Limit:" Foreground="{StaticResource FgBrush}"
                                                   VerticalAlignment="Center" Margin="0,0,8,0"/>
                                        <TextBox   Grid.Column="1" x:Name="KqlTakeTxt" Text="100"/>
                                        <TextBlock Grid.Column="2" Text="Mode:" Foreground="{StaticResource FgBrush}"
                                                   VerticalAlignment="Center" Margin="20,0,8,0"/>
                                        <ComboBox  Grid.Column="3" x:Name="KqlTakeMode"/>
                                    </Grid>

                                    <TextBlock Text="EMITTED PIPELINE ORDER" Style="{StaticResource SectionHeader}"
                                               Background="Transparent" Padding="0,24,0,8"/>
                                    <TextBlock Foreground="{StaticResource FgDimBrush}" FontSize="11"
                                               TextWrapping="Wrap" LineHeight="20" FontFamily="Consolas">
                                        Table → where (time) → where (filters) → extend → project / project-away → summarize (with bin) → order by → take / top
                                    </TextBlock>
                                    <TextBlock Foreground="{StaticResource FgDimBrush}" FontSize="11"
                                               TextWrapping="Wrap" LineHeight="20" Margin="0,12,0,0">
                                        <Run>The builder enforces this order regardless of which sub-tab you fill in first. "filter early" is the most consequential KQL performance rule - the builder always emits time and where filters before any reshape.</Run>
                                    </TextBlock>
                                </StackPanel>
                            </ScrollViewer>
                        </TabItem>

                        <!-- ===== Templates ===== -->
                        <TabItem Header="Templates">
                            <DockPanel LastChildFill="True">
                                <Border DockPanel.Dock="Top"
                                        Background="{StaticResource BgAltBrush}"
                                        BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                                        Padding="12,8,12,8">
                                    <StackPanel Orientation="Horizontal">
                                        <Button x:Name="KqlApplyTemplateBtn" Content="Load Template" Style="{StaticResource DarkButton}"/>
                                        <TextBlock Foreground="{StaticResource FgDimBrush}"
                                                   VerticalAlignment="Center" Margin="14,0,0,0" FontSize="10">
                                            Select a template, click Load Template, the query appears in the box below. Edit freely.
                                        </TextBlock>
                                    </StackPanel>
                                </Border>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="2*" MinWidth="200"/>
                                        <ColumnDefinition Width="6"/>
                                        <ColumnDefinition Width="3*" MinWidth="280"/>
                                    </Grid.ColumnDefinitions>
                                    <ListBox Grid.Column="0" x:Name="KqlTemplatesList"
                                             Background="{StaticResource BgBrush}" BorderThickness="0"
                                             FontSize="11"/>
                                    <GridSplitter Grid.Column="1" Width="6"
                                                  HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                                                  ResizeBehavior="PreviousAndNext" ResizeDirection="Columns" Cursor="SizeWE"/>
                                    <TextBox Grid.Column="2" x:Name="KqlTemplatePreviewTxt"
                                             IsReadOnly="True" AcceptsReturn="True"
                                             VerticalScrollBarVisibility="Auto"
                                             HorizontalScrollBarVisibility="Auto"
                                             FontFamily="Consolas" FontSize="13"
                                             Foreground="{StaticResource FgBrush}"
                                             Background="{StaticResource BgPanelBrush}" BorderThickness="0"
                                             Padding="14,10,14,10"/>
                                </Grid>
                            </DockPanel>
                        </TabItem>

                        <!-- ===== Reference ===== -->
                        <TabItem Header="Reference">
                            <ScrollViewer>
                                <StackPanel Margin="20,16,20,16">
                                    <TextBlock Text="OPERATORS (PIPELINE ORDER)" Style="{StaticResource SectionHeader}"
                                               Background="Transparent" Padding="0,0,0,8"/>
                                    <TextBlock Foreground="{StaticResource FgBrush}" FontFamily="Consolas" FontSize="12"
                                               TextWrapping="Wrap" LineHeight="22" xml:space="preserve"><Run Foreground="#58A6FF">where</Run><Run>  -  filter rows. Apply earliest. Cheapest predicates first.</Run><LineBreak/><Run Foreground="#58A6FF">parse / parse-kv</Run><Run>  -  extract structured fields from a string column.</Run><LineBreak/><Run Foreground="#58A6FF">extract / extract_all</Run><Run>  -  regex captures.</Run><LineBreak/><Run Foreground="#58A6FF">extend</Run><Run>  -  compute new columns.</Run><LineBreak/><Run Foreground="#58A6FF">project / project-away / project-keep / project-rename / project-reorder</Run><Run>  -  shape the column set.</Run><LineBreak/><Run Foreground="#58A6FF">distinct</Run><Run>  -  de-duplicate rows on the listed columns.</Run><LineBreak/><Run Foreground="#58A6FF">summarize</Run><Run>  -  aggregations. arg_max(*, key) returns the latest row per key.</Run><LineBreak/><Run Foreground="#58A6FF">join / lookup / union</Run><Run>  -  combine multiple tables.</Run><LineBreak/><Run Foreground="#58A6FF">mv-expand / mv-apply</Run><Run>  -  flatten/iterate over array columns.</Run><LineBreak/><Run Foreground="#58A6FF">order by / sort by</Run><Run>  -  sorting. Avoid early; expensive.</Run><LineBreak/><Run Foreground="#58A6FF">take / top</Run><Run>  -  row limits. take is non-deterministic; top is sorted.</Run></TextBlock>

                                    <TextBlock Text="SCALAR FUNCTIONS" Style="{StaticResource SectionHeader}"
                                               Background="Transparent" Padding="0,20,0,8"/>
                                    <TextBlock Foreground="{StaticResource FgBrush}" FontFamily="Consolas" FontSize="12"
                                               TextWrapping="Wrap" LineHeight="22" xml:space="preserve"><Run Foreground="#58A6FF">Time:</Run><Run>          ago(), now(), startofday(), endofday(), bin(), datetime_diff(), format_datetime(), todatetime(), totimespan(), hourofday(), dayofweek()</Run><LineBreak/><Run Foreground="#58A6FF">String:</Run><Run>        strcat(), substring(), split(), replace_string(), trim(), tolower(), toupper(), strlen(), parse_json(), parse_url(), extract(), extract_all()</Run><LineBreak/><Run Foreground="#58A6FF">Type:</Run><Run>          tostring(), toint(), tolong(), todouble(), tobool(), todynamic()</Run><LineBreak/><Run Foreground="#58A6FF">Math:</Run><Run>          abs(), round(), floor(), ceiling(), pow(), log(), sqrt()</Run><LineBreak/><Run Foreground="#58A6FF">Conditional:</Run><Run>   iff(cond, then, else), case(c1, v1, c2, v2, default), coalesce(...)</Run><LineBreak/><Run Foreground="#58A6FF">Set:</Run><Run>           x in (a,b,c), x in~ (a,b,c) [case insensitive], x !in (a,b,c), set_intersect(), set_union(), set_difference(), array_length()</Run></TextBlock>

                                    <TextBlock Text="AGGREGATION FUNCTIONS" Style="{StaticResource SectionHeader}"
                                               Background="Transparent" Padding="0,20,0,8"/>
                                    <TextBlock Foreground="{StaticResource FgBrush}" FontFamily="Consolas" FontSize="12"
                                               TextWrapping="Wrap" LineHeight="22" xml:space="preserve"><Run>count(), countif(predicate), dcount(col), dcountif(col, pred), sum(col), avg(col), min(col), max(col),</Run><LineBreak/><Run>percentile(col, p), percentiles(col, p1, p2, ...), stdev(col), variance(col),</Run><LineBreak/><Run>make_set(col), make_set_if(col, pred), make_list(col), make_list_if(col, pred),</Run><LineBreak/><Run Foreground="#58A6FF">arg_min(expr, *) / arg_max(expr, *)</Run><Run>  -  return the row with min/max expr. The operator you'll use weekly.</Run><LineBreak/><Run Foreground="#58A6FF">take_any(col)</Run><Run>  -  pick any value (cheap, non-deterministic).</Run></TextBlock>

                                    <TextBlock Text="DATATABLE / EXTERNALDATA" Style="{StaticResource SectionHeader}"
                                               Background="Transparent" Padding="0,20,0,8"/>
                                    <TextBlock Foreground="{StaticResource FgBrush}" FontFamily="Consolas" FontSize="12"
                                               TextWrapping="Wrap" LineHeight="22" xml:space="preserve"><Run Foreground="#58A6FF">datatable</Run><Run>  -  inline reference data, e.g. a watchlist:</Run><LineBreak/><Run>    let HighValueAccts = datatable(Account:string, Tier:int)["ADMIN-DBA",0,"SVC-BACKUP",1];</Run><LineBreak/><Run Foreground="#58A6FF">externaldata</Run><Run>  -  read CSV/TSV from a URL at query time.</Run><LineBreak/><Run Foreground="#58A6FF">_GetWatchlist("Name")</Run><Run>  -  Sentinel-managed watchlists.</Run>
                                    </TextBlock>
                                </StackPanel>
                            </ScrollViewer>
                        </TabItem>

                    </TabControl>

                    <!-- Splitter between sub-tabs and generated query area -->
                    <GridSplitter Grid.Row="2" Height="6"
                                  HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                                  ResizeBehavior="PreviousAndNext" ResizeDirection="Rows" Cursor="SizeNS"/>

                    <!-- Generated KQL output -->
                    <Border Grid.Row="3"
                            Background="{StaticResource BgPanelBrush}"
                            BorderBrush="{StaticResource BorderBrush}"
                            BorderThickness="1" CornerRadius="6"
                            Margin="10,4,10,10">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <Grid Grid.Row="0" Background="{StaticResource BgAltBrush}">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="GENERATED KQL" Style="{StaticResource SectionHeader}"
                                           Background="Transparent"/>
                                <TextBlock Grid.Column="1" x:Name="KqlOutputStatusLbl"
                                           Foreground="{StaticResource FgDimBrush}" FontSize="10"
                                           VerticalAlignment="Center" Padding="0,0,14,0"/>
                            </Grid>
                            <TextBox Grid.Row="1" x:Name="KqlOutputTxt"
                                     AcceptsReturn="True" AcceptsTab="True"
                                     IsReadOnly="False"
                                     FontFamily="Consolas" FontSize="13"
                                     VerticalScrollBarVisibility="Auto"
                                     HorizontalScrollBarVisibility="Auto"
                                     Foreground="{StaticResource FgBrush}"
                                     Background="{StaticResource BgPanelBrush}"
                                     BorderThickness="0"
                                     Padding="14,10,14,10"
                                     SpellCheck.IsEnabled="False"/>
                        </Grid>
                    </Border>
                </Grid>
            </TabItem>

            <!-- ============= CVEs tab ============= -->
            <TabItem Header="CVEs" x:Name="CvesTab">
                <DockPanel LastChildFill="True">
                    <Border DockPanel.Dock="Top"
                            Background="{StaticResource BgAltBrush}"
                            BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                            Padding="12,8,12,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Grid.Column="0" Text="SEARCH &gt;" Style="{StaticResource SearchPrompt}"/>
                            <TextBox   Grid.Column="1" x:Name="CvesSearchTxt" Margin="0,0,8,0"/>
                            <Button    Grid.Column="2" x:Name="CvesFilterBtn" Content="Filter" Style="{StaticResource DarkButton}"/>
                            <Button    Grid.Column="3" x:Name="CvesClearBtn"  Content="Clear"  Style="{StaticResource DarkButton}"/>
                            <TextBlock Grid.Column="4" x:Name="CvesCountLbl"  Style="{StaticResource CountLabel}"/>
                        </Grid>
                    </Border>
                    <DataGrid x:Name="CvesGrid"/>
                </DockPanel>
            </TabItem>

            <!-- ============= KEVs tab ============= -->
            <TabItem Header="KEVs" x:Name="KevsTab">
                <DockPanel LastChildFill="True">
                    <Border DockPanel.Dock="Top"
                            Background="{StaticResource BgAltBrush}"
                            BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                            Padding="12,8,12,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Grid.Column="0" Text="SEARCH &gt;" Style="{StaticResource SearchPrompt}"/>
                            <TextBox   Grid.Column="1" x:Name="KevsSearchTxt" Margin="0,0,8,0"/>
                            <Button    Grid.Column="2" x:Name="KevsFilterBtn" Content="Filter" Style="{StaticResource DarkButton}"/>
                            <Button    Grid.Column="3" x:Name="KevsClearBtn"  Content="Clear"  Style="{StaticResource DarkButton}"/>
                            <TextBlock Grid.Column="4" x:Name="KevsCountLbl"  Style="{StaticResource CountLabel}"/>
                        </Grid>
                    </Border>
                    <DataGrid x:Name="KevsGrid"/>
                </DockPanel>
            </TabItem>

            <!-- ============= IoC Search tab ============= -->
            <TabItem Header="IoC Search" x:Name="IocTab">
                <DockPanel LastChildFill="True">
                    <Border DockPanel.Dock="Top"
                            Background="{StaticResource BgAltBrush}"
                            BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                            Padding="12,8,12,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Grid.Column="0" Text="IOC / KEYWORD &gt;" Style="{StaticResource SearchPrompt}"/>
                            <TextBox   Grid.Column="1" x:Name="IocSearchTxt" Margin="0,0,8,0"/>
                            <Button    Grid.Column="2" x:Name="IocSearchBtn" Content="Search" Style="{StaticResource DarkButton}"/>
                            <TextBlock Grid.Column="3" x:Name="IocCountLbl"  Style="{StaticResource CountLabel}"/>
                        </Grid>
                    </Border>
                    <DataGrid x:Name="IocGrid"/>
                </DockPanel>
            </TabItem>

            <!-- ============= Threat Intel tab ============= -->
            <TabItem Header="Threat Intel" x:Name="ThreatIntelTab">
                <DockPanel LastChildFill="True">
                    <Border DockPanel.Dock="Top"
                            Background="{StaticResource BgAltBrush}"
                            BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1"
                            Padding="12,8,12,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Grid.Column="0" Text="LOOKUP &gt;" Style="{StaticResource SearchPrompt}"/>
                            <TextBox   Grid.Row="0" Grid.Column="1" x:Name="TiInputTxt"
                                       ToolTip="IPv4/IPv6, domain, URL, MD5/SHA1/SHA256 hash, or vendor:product"
                                       Margin="0,0,8,0"/>
                            <Button    Grid.Row="0" Grid.Column="2" x:Name="TiLookupBtn"   Content="Lookup"   Style="{StaticResource DarkButton}"/>
                            <Button    Grid.Row="0" Grid.Column="3" x:Name="TiAddIocBtn"   Content="+ IoC"    Style="{StaticResource DarkButton}"
                                       ToolTip="Save the input as an IoC in the Iocs table"/>
                            <Button    Grid.Row="0" Grid.Column="4" x:Name="TiClearBtn"    Content="Clear"    Style="{StaticResource DarkButton}"/>
                            <StackPanel Grid.Row="1" Grid.ColumnSpan="5" Orientation="Horizontal" Margin="0,8,0,0">
                                <TextBlock x:Name="TiTypeLbl"      Foreground="{StaticResource FgDimBrush}" FontSize="11" Margin="0,0,18,0" Text="type: -"/>
                                <TextBlock x:Name="TiProvidersLbl" Foreground="{StaticResource FgDimBrush}" FontSize="11" Margin="0,0,18,0" Text="providers: -"/>
                                <TextBlock x:Name="TiStatusLbl"    Foreground="{StaticResource AccentBrush}" FontSize="11" Text=""/>
                            </StackPanel>
                        </Grid>
                    </Border>
                    <DataGrid x:Name="TiGrid" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Source"     Binding="{Binding Source}"          Width="120"/>
                            <DataGridTextColumn Header="Verdict"    Binding="{Binding Verdict}"         Width="110"/>
                            <DataGridTextColumn Header="Family"     Binding="{Binding Family}"          Width="160"/>
                            <DataGridTextColumn Header="Detection"  Binding="{Binding DetectionRatio}"  Width="170"/>
                            <DataGridTextColumn Header="Reputation" Binding="{Binding Reputation}"      Width="80"/>
                            <DataGridTextColumn Header="Tags"       Binding="{Binding Tags}"            Width="*"/>
                            <DataGridTextColumn Header="Cached"     Binding="{Binding Cached}"          Width="90"/>
                            <DataGridTextColumn Header="Url"        Binding="{Binding ProviderUrl}"     Width="200"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </DockPanel>
            </TabItem>

        </TabControl>
    </Grid>
</Window>
'@

# ============================================================
# Load XAML and bind named elements
# ============================================================
try {
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
} catch {
    throw "Failed to parse XAML: $_"
}

$elementNames = @(
    # Persistent header
    'LastRefreshLbl','RefreshBtn',
    'BtnUpdateKev','BtnUpdateCve','BtnUpdateEpss','BtnUpdateMitre','JobStatusLbl',
    # TabControls and TabItems
    'MainTabs','MitreSubTabs',
    'DashboardTab','MitreTab','TacticsTab','TechniquesTab','SubTechniquesTab',
    'GroupsTab','SoftwareTab','MitigationsTab','CvesTab','KevsTab','IocTab',
    # Dashboard KPIs and grids
    'KpiFeedValue','KpiFeedSub',
    'KpiKevValue','KpiKevSub',
    'KpiCveValue','KpiCveSub',
    'KpiRanValue','KpiRanSub',
    'NewKevGrid','FeedGrid','CritCveGrid',
    # Grid tabs (8 of them, 5 elements each)
    'TacticsGrid','TacticsSearchTxt','TacticsFilterBtn','TacticsClearBtn','TacticsCountLbl',
    'TechniquesGrid','TechniquesSearchTxt','TechniquesFilterBtn','TechniquesClearBtn','TechniquesCountLbl',
    'SubTechniquesGrid','SubTechniquesSearchTxt','SubTechniquesFilterBtn','SubTechniquesClearBtn','SubTechniquesCountLbl',
    'GroupsGrid','GroupsSearchTxt','GroupsFilterBtn','GroupsClearBtn','GroupsCountLbl',
    'SoftwareGrid','SoftwareSearchTxt','SoftwareFilterBtn','SoftwareClearBtn','SoftwareCountLbl',
    'MitigationsGrid','MitigationsSearchTxt','MitigationsFilterBtn','MitigationsClearBtn','MitigationsCountLbl',
    'CvesGrid','CvesSearchTxt','CvesFilterBtn','CvesClearBtn','CvesCountLbl',
    'KevsGrid','KevsSearchTxt','KevsFilterBtn','KevsClearBtn','KevsCountLbl',
    # IoC tab
    'IocGrid','IocSearchTxt','IocSearchBtn','IocCountLbl',
    # Threat Intel tab
    'ThreatIntelTab',
    'TiInputTxt','TiLookupBtn','TiAddIocBtn','TiClearBtn',
    'TiTypeLbl','TiProvidersLbl','TiStatusLbl','TiGrid',
    # KQL Builder
    'KqlTab','KqlSubTabs',
    'KqlTableCombo','KqlTimeCombo','KqlCustomTimeTxt',
    'KqlBuildBtn','KqlCopyBtn','KqlResetBtn',
    'KqlAddFilterBtn','KqlClearFiltersBtn','KqlFiltersStack',
    'KqlAddExtendBtn','KqlClearExtendBtn','KqlExtendStack',
    'KqlProjectMode_Project','KqlProjectMode_ProjectAway',
    'KqlProjectAllBtn','KqlProjectNoneBtn','KqlProjectList',
    'KqlAddAggBtn','KqlClearAggBtn','KqlAggStack',
    'KqlBinTimeCombo','KqlGroupByTxt',
    'KqlOrderColCombo','KqlOrderDirCombo','KqlTakeTxt','KqlTakeMode',
    'KqlTemplatesList','KqlTemplatePreviewTxt','KqlApplyTemplateBtn',
    'KqlOutputTxt','KqlOutputStatusLbl'
)
foreach ($n in $elementNames) {
    Set-Variable -Name $n -Value ($window.FindName($n)) -Scope Script
}

# Theme brushes for dynamic color changes
$AccentBrush    = $window.FindResource('AccentBrush')
$AccentAltBrush = $window.FindResource('AccentAltBrush')
$WarnBrush      = $window.FindResource('WarnBrush')
$DangerBrush    = $window.FindResource('DangerBrush')

# ============================================================
# Dashboard refresh
# ============================================================
$refreshDash = {
    try {
        $db = $script:DbPath
        if (-not (Test-Path $db)) {
            $LastRefreshLbl.Text = 'DB not found - run feed scripts first'
            return
        }

        # Feed health
        $feeds = Invoke-SqliteQuery -DataSource $db -Query "SELECT FeedName, LastUpdated, RecordCount FROM FeedMeta"
        $now = Get-Date
        $feedRows = New-Object System.Collections.Generic.List[object]
        $stale = 0
        foreach ($f in $feeds) {
            $dt = $null
            try { $dt = [DateTime]::Parse($f.LastUpdated) } catch {}
            $age = ''; $status = 'OK'
            if ($dt) {
                $hours = [int]($now - $dt).TotalHours
                $age = if ($hours -lt 48) { "$hours h" } else { "$([int]($hours/24)) d" }
                if ($f.FeedName -like '*MITRE*') {
                    if ($hours -gt 720) { $status = 'STALE'; $stale++ }
                } else {
                    if ($hours -gt 48)  { $status = 'STALE'; $stale++ }
                }
            } else { $status = 'UNKNOWN'; $stale++ }
            $feedRows.Add([PSCustomObject]@{
                Feed        = [string]$f.FeedName
                LastUpdated = if ($dt) { $dt.ToString('yyyy-MM-dd HH:mm') } else { '' }
                Age         = $age
                Records     = [string]$f.RecordCount
                Status      = $status
            })
        }
        $FeedGrid.ItemsSource = $feedRows

        # KPI 1: feed status
        $tot = $feedRows.Count
        $okCount = [Math]::Max(0, $tot - $stale)
        $KpiFeedValue.Text = if ($tot -gt 0) { "$okCount/$tot OK" } else { '--' }
        $KpiFeedSub.Text   = if ($tot -eq 0)    { 'no feeds ingested yet' }
                              elseif ($stale -gt 0) { "$stale stale feed(s)" }
                              else                  { 'all feeds fresh' }
        $KpiFeedValue.Foreground = if ($stale -gt 0 -or $tot -eq 0) { $WarnBrush } else { $AccentAltBrush }

        # KPI 2: KEV total
        $kev = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM KEVs").C
        $KpiKevValue.Text       = "$kev"
        $KpiKevValue.Foreground = $AccentBrush
        $KpiKevSub.Text         = 'CISA known-exploited'

        # KPI 3: critical CVEs
        $crit = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM CVEs WHERE CvssScore >= 9.0").C
        $KpiCveValue.Text       = "$crit"
        $KpiCveValue.Foreground = if ($crit -gt 0) { $WarnBrush } else { $AccentBrush }
        $KpiCveSub.Text         = 'CVSS >= 9.0 in cache'

        # KPI 4: ransomware-linked
        $ran = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM KEVs WHERE KnownRansomware = 'Known'").C
        $KpiRanValue.Text       = "$ran"
        $KpiRanValue.Foreground = if ($ran -gt 0) { $DangerBrush } else { $AccentBrush }
        $KpiRanSub.Text         = 'ransomware-linked'

        # Newest KEVs
        $nk = Invoke-SqliteQuery -DataSource $db -Query "SELECT DateAdded, CveId, VendorProject, Product, VulnName, KnownRansomware FROM KEVs ORDER BY DateAdded DESC LIMIT 25"
        $kevList = New-Object System.Collections.Generic.List[object]
        foreach ($r in $nk) {
            $kevList.Add([PSCustomObject]@{
                DateAdded     = [string]$r.DateAdded
                CveId         = [string]$r.CveId
                VendorProject = [string]$r.VendorProject
                Product       = [string]$r.Product
                VulnName      = [string]$r.VulnName
                Ransomware    = [string]$r.KnownRansomware
            })
        }
        $NewKevGrid.ItemsSource = $kevList

        # Critical CVEs - surface CVSS x EPSS-percentile ranking when EPSS is loaded.
        # Falls back to CvssScore alone when EpssPercentile is null (treats it as 0.5).
        $cc = Invoke-SqliteQuery -DataSource $db -Query @"
SELECT CveId, CvssScore, Severity, EpssScore, EpssPercentile,
       (CvssScore * COALESCE(EpssPercentile, 0.5)) AS RiskScore,
       substr(Description, 1, 160) AS Snippet
FROM CVEs
WHERE CvssScore >= 9.0
ORDER BY RiskScore DESC, Published DESC
LIMIT 25
"@
        $cveList = New-Object System.Collections.Generic.List[object]
        foreach ($r in $cc) {
            $epssPct = if ($null -ne $r.EpssPercentile -and $r.EpssPercentile -ne [System.DBNull]::Value) {
                "{0:N1}%" -f ([double]$r.EpssPercentile * 100)
            } else { '-' }
            $risk = if ($null -ne $r.RiskScore -and $r.RiskScore -ne [System.DBNull]::Value) {
                "{0:N2}" -f [double]$r.RiskScore
            } else { '-' }
            $cveList.Add([PSCustomObject]@{
                CveId     = [string]$r.CveId
                CvssScore = [string]$r.CvssScore
                EpssPct   = $epssPct
                Risk      = $risk
                Severity  = [string]$r.Severity
                Snippet   = [string]$r.Snippet
            })
        }
        $CritCveGrid.ItemsSource = $cveList

        $LastRefreshLbl.Text = "Last refresh: $($now.ToString('HH:mm:ss'))"
    } catch {
        [System.Windows.MessageBox]::Show("Dashboard refresh failed:`n$_", 'Dashboard Error', 'OK', 'Error') | Out-Null
    }
}
$DashboardTab.Tag = @{ Loader = $refreshDash }

# ============================================================
# Generic grid-tab initializer (search/filter/clear/auto-load)
# ============================================================
function Initialize-GridTab {
    param(
        $TabItem, $Grid, $SearchTxt, $FilterBtn, $ClearBtn, $CountLbl,
        [string]$BaseQuery, [string[]]$FilterCols
    )

    # Capture the script-scoped DB path into a local variable so
    # GetNewClosure() preserves it. $script:DbPath does not necessarily
    # resolve back to the calling script once a closure runs in its
    # own bound execution context.
    $dbPath = $script:DbPath

    $loadData = {
        param([string]$searchTerm)
        try {
            $q = $BaseQuery
            $sqlParams = $null
            if ($searchTerm) {
                $likes = $FilterCols | ForEach-Object { "$_ LIKE @s" }
                if ($q -match '\sORDER BY\s') {
                    $q = $q -replace '(\sORDER BY\s)', " WHERE ($($likes -join ' OR '))`$1"
                } else {
                    $q += " WHERE " + ($likes -join ' OR ')
                }
                $sqlParams = @{ s = "%$searchTerm%" }
            }
            $rows = if ($sqlParams) {
                Invoke-SqliteQuery -DataSource $dbPath -Query $q -SqlParameters $sqlParams
            } else {
                Invoke-SqliteQuery -DataSource $dbPath -Query $q
            }
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($r in $rows) {
                $obj = [ordered]@{}
                foreach ($p in $r.PSObject.Properties) {
                    $val = $p.Value
                    if ($null -ne $val -and $val.ToString().Length -gt 300) {
                        $obj[$p.Name] = $val.ToString().Substring(0, 297) + '...'
                    } else {
                        $obj[$p.Name] = [string]$val
                    }
                }
                $list.Add([PSCustomObject]$obj)
            }
            $Grid.ItemsSource = $list
            $CountLbl.Text    = "$($list.Count) rows"
        } catch {
            $CountLbl.Text = "Load failed: $($_.Exception.Message)"
        }
    }.GetNewClosure()

    $loader = { & $loadData $SearchTxt.Text }.GetNewClosure()
    $Grid.Tag    = @{ Loader = $loader }
    if ($TabItem) { $TabItem.Tag = @{ Loader = $loader } }

    $FilterBtn.Add_Click({ & $loadData $SearchTxt.Text }.GetNewClosure())
    $ClearBtn.Add_Click({  $SearchTxt.Text = ''; & $loadData $null }.GetNewClosure())
    $SearchTxt.Add_KeyDown({
        param($s, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Return) {
            & $loadData $SearchTxt.Text
            $e.Handled = $true
        }
    }.GetNewClosure())

    & $loadData $null   # initial load
}

# ============================================================
# Wire up grid tabs
# ============================================================
$gridTabConfigs = @(
    @{ Prefix='Tactics';       Tab=$TacticsTab;       Query='SELECT ExternalId, Name, ShortName, Description, Url FROM Tactics ORDER BY ExternalId';                                                                                              Cols=@('Name','ShortName','Description') }
    @{ Prefix='Techniques';    Tab=$TechniquesTab;    Query='SELECT ExternalId, Name, Tactics, Platforms, DataSources, Detection, Description, Url FROM Techniques WHERE IsSubtechnique = 0 ORDER BY ExternalId';                                  Cols=@('Name','Tactics','Platforms','DataSources','Detection','Description') }
    @{ Prefix='SubTechniques'; Tab=$SubTechniquesTab; Query='SELECT ExternalId, Name, ParentExternalId, Tactics, Platforms, Detection, Description, Url FROM Techniques WHERE IsSubtechnique = 1 ORDER BY ExternalId';                              Cols=@('Name','ParentExternalId','Tactics','Platforms','Detection','Description') }
    @{ Prefix='Groups';        Tab=$GroupsTab;        Query='SELECT ExternalId, Name, Aliases, Description, Url FROM AttackGroups ORDER BY ExternalId';                                                                                            Cols=@('Name','Aliases','Description') }
    @{ Prefix='Software';      Tab=$SoftwareTab;      Query='SELECT ExternalId, Name, Type, Aliases, Platforms, Description, Url FROM Software ORDER BY ExternalId';                                                                                Cols=@('Name','Aliases','Platforms','Description') }
    @{ Prefix='Mitigations';   Tab=$MitigationsTab;   Query='SELECT ExternalId, Name, Description, Url FROM Mitigations ORDER BY ExternalId';                                                                                                       Cols=@('Name','Description') }
    @{ Prefix='Cves';          Tab=$CvesTab;          Query='SELECT CveId, Published, Severity, CvssScore, EpssScore, EpssPercentile, EpssDate, Vector, Description FROM CVEs ORDER BY (CvssScore * COALESCE(EpssPercentile, 0.5)) DESC, Published DESC';   Cols=@('CveId','Severity','Description','Vector') }
    @{ Prefix='Kevs';          Tab=$KevsTab;          Query='SELECT CveId, VendorProject, Product, VulnName, DateAdded, KnownRansomware, DueDate, RequiredAction, Description FROM KEVs ORDER BY DateAdded DESC';                                   Cols=@('CveId','VendorProject','Product','VulnName','Description') }
)

foreach ($cfg in $gridTabConfigs) {
    $p = $cfg.Prefix
    Initialize-GridTab `
        -TabItem    $cfg.Tab `
        -Grid       (Get-Variable -Name "${p}Grid"      -ValueOnly) `
        -SearchTxt  (Get-Variable -Name "${p}SearchTxt" -ValueOnly) `
        -FilterBtn  (Get-Variable -Name "${p}FilterBtn" -ValueOnly) `
        -ClearBtn   (Get-Variable -Name "${p}ClearBtn"  -ValueOnly) `
        -CountLbl   (Get-Variable -Name "${p}CountLbl"  -ValueOnly) `
        -BaseQuery  $cfg.Query `
        -FilterCols $cfg.Cols
}

# ============================================================
# IoC / Global Search tab - UNION ALL across every textual table
# ============================================================
$iocSearch = {
    $term = $IocSearchTxt.Text
    if (-not $term) { return }
    # Searches across:
    #   - MITRE ATT&CK content (Techniques, Groups, Software, Mitigations)
    #   - Vulnerability feeds (CVEs, KEVs)
    #   - Analyst-curated IoCs (Iocs table)
    #   - Cached threat-intel enrichment from VT/OTX/URLScan/AbuseIPDB/NSRL/NIST (IntelCache)
    #   - Hash reputation cache from existing module (HashIntel)
    $q = @"
SELECT 'Technique'  AS Source, ExternalId AS Id,        Name                                  AS Name,    substr(Description,1,300) AS Snippet, Url AS Url FROM Techniques   WHERE Name LIKE @s OR Description LIKE @s OR Detection LIKE @s
UNION ALL
SELECT 'Group',       ExternalId,                       Name,                                             substr(Description,1,300),            Url        FROM AttackGroups WHERE Name LIKE @s OR Aliases LIKE @s OR Description LIKE @s
UNION ALL
SELECT 'Software',    ExternalId,                       Name,                                             substr(Description,1,300),            Url        FROM Software     WHERE Name LIKE @s OR Aliases LIKE @s OR Description LIKE @s
UNION ALL
SELECT 'Mitigation',  ExternalId,                       Name,                                             substr(Description,1,300),            Url        FROM Mitigations  WHERE Name LIKE @s OR Description LIKE @s
UNION ALL
SELECT 'CVE',         CveId,                            CveId,                                            substr(Description,1,300),            ''         FROM CVEs          WHERE CveId LIKE @s OR Description LIKE @s
UNION ALL
SELECT 'KEV',         CveId,                            VulnName,                                         substr(Description,1,300),            ''         FROM KEVs          WHERE CveId LIKE @s OR VendorProject LIKE @s OR Product LIKE @s OR VulnName LIKE @s OR Description LIKE @s
UNION ALL
SELECT 'IoC:'||Type,  COALESCE(Value,''),               COALESCE(Tags,'')||' ['||COALESCE(Source,'')||']', substr(COALESCE(Notes,''),1,300),     ''         FROM Iocs          WHERE Value LIKE @s OR Tags LIKE @s OR Notes LIKE @s
UNION ALL
SELECT 'Intel:'||Source, COALESCE(IocValue,''),          UPPER(COALESCE(Verdict,'unknown'))||' '||COALESCE(Family,''), substr(COALESCE(DetectionRatio,'')||' '||COALESCE(Tags,''),1,300), COALESCE(ProviderUrl,'') FROM IntelCache WHERE IocValue LIKE @s OR Family LIKE @s OR Tags LIKE @s
UNION ALL
SELECT 'Hash:'||Source, Sha256,                          UPPER(COALESCE(Verdict,'unknown'))||' '||COALESCE(FamilyName,''), substr(COALESCE(DetectionRatio,'')||' '||COALESCE(Tags,''),1,300), '' FROM HashIntel  WHERE Sha256 LIKE @s OR Md5 LIKE @s OR Sha1 LIKE @s OR FamilyName LIKE @s
"@
    try {
        $rows = Invoke-SqliteQuery -DataSource $script:DbPath -Query $q -SqlParameters @{ s = "%$term%" }
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $list.Add([PSCustomObject]@{
                Source  = [string]$r.Source
                Id      = [string]$r.Id
                Name    = [string]$r.Name
                Snippet = [string]$r.Snippet
                Url     = [string]$r.Url
            })
        }
        $IocGrid.ItemsSource = $list
        $IocCountLbl.Text    = "$($list.Count) hits"
    } catch {
        $IocCountLbl.Text = "Search failed: $($_.Exception.Message)"
    }
}
$IocSearchBtn.Add_Click($iocSearch)
$IocSearchTxt.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Return) {
        & $iocSearch
        $e.Handled = $true
    }
})

# ============================================================
# Threat Intel tab
# - Auto-detects IoC type from the input
# - Fans out to every compatible provider in a runspace pool
# - Streams results back to the UI as each provider returns
# - "+ IoC" button stores the input in the Iocs table for later
# ============================================================

# Dot-source the dispatcher (which dot-sources every provider module).
. (Join-Path $script:ModulesDir 'SecIntel.ThreatIntel.ps1')

# Show provider configuration on tab activation. Implemented inline against
# the AppSettings table directly - WPF event handler closures can't reliably
# see dot-sourced functions like Get-IntelProviderStatus or Get-AppSecret,
# but Invoke-SqliteQuery is from a binary-imported module and is always
# globally visible. Result is the same status table without the indirection.
$tiDbForStatus = $script:DbPath
$tiProviderKeys = @(
    @{ Display='VirusTotal';    Setting='apikey.virustotal';    Required=$true  }
    @{ Display='OTX';           Setting='apikey.otx';           Required=$true  }
    @{ Display='AbuseIPDB';     Setting='apikey.abuseipdb';     Required=$true  }
    @{ Display='URLScan';       Setting='apikey.urlscan';       Required=$false }   # public scans work without
    @{ Display='NSRL/CIRCL';    Setting=$null;                  Required=$false }   # always available
    @{ Display='NIST NVD';      Setting='apikey.nvd';           Required=$false }   # works without, faster with
    @{ Display='MalwareBazaar'; Setting='apikey.malwarebazaar'; Required=$true  }   # required as of 2024
)
$updateProvidersLabel = {
    try {
        $parts = foreach ($p in $tiProviderKeys) {
            $configured = $true
            if ($p.Setting) {
                $row = Invoke-SqliteQuery -DataSource $tiDbForStatus `
                    -Query "SELECT 1 AS X FROM AppSettings WHERE Name=@n AND Value IS NOT NULL AND length(Value) > 0" `
                    -SqlParameters @{ n=$p.Setting } | Select-Object -First 1
                $configured = [bool]$row
                # If a key isn't required (e.g. URLScan), still show as available
                if (-not $configured -and -not $p.Required) { $configured = $true }
            }
            $glyph = if ($configured) { [char]0x2713 } else { [char]0x00D7 }
            "$($p.Display)$glyph"
        }
        $TiProvidersLbl.Text = 'providers: ' + ($parts -join '  ')
    } catch {
        $TiProvidersLbl.Text = "providers: (error - $($_.Exception.Message))"
    }
}.GetNewClosure()

$tiAutoDetect = {
    param([string]$value)
    # Inlined type detection. The dispatcher's Resolve-IocType isn't always
    # visible from inside a WPF-dispatched click handler closure (cross-scope
    # function lookup gets flaky in that path), so we duplicate the regex here.
    # Order matters: most specific patterns first.
    if (-not $value) { return $null }
    $v = $value.Trim()
    if (-not $v) { return $null }
    if ($v -match '^[a-fA-F0-9]{64}$') { return 'sha256' }
    if ($v -match '^[a-fA-F0-9]{40}$') { return 'sha1'   }
    if ($v -match '^[a-fA-F0-9]{32}$') { return 'md5'    }
    if ($v -match '^[a-zA-Z][a-zA-Z0-9+\-.]*://') { return 'url' }
    if ($v -match '^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$') { return 'ip' }
    if ($v -match '^[0-9a-fA-F:]+$' -and $v -match ':' -and $v.Length -le 39) { return 'ipv6' }
    if ($v -match '^[a-z0-9_\-]+:[a-z0-9_\-]+$') { return 'product' }
    if ($v -match '^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') { return 'domain' }
    return $null
}.GetNewClosure()

# Capture the WPF dispatcher so background runspaces can marshal results
# back to the UI thread without throwing cross-thread access exceptions.
$tiDispatcher = $window.Dispatcher
$tiResultList = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$TiGrid.ItemsSource = $tiResultList

$tiClear = {
    $tiResultList.Clear()
    $TiInputTxt.Text   = ''
    $TiTypeLbl.Text    = 'type: -'
    $TiStatusLbl.Text  = ''
}.GetNewClosure()
$TiClearBtn.Add_Click($tiClear)

$tiAddIoc = {
    $val = $TiInputTxt.Text.Trim()
    if (-not $val) { return }
    $type = & $tiAutoDetect $val
    if (-not $type) { $TiStatusLbl.Text = "could not detect IoC type"; return }
    try {
        Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT INTO Iocs (Type, Value, Source, FirstSeen, LastSeen, Confidence, Tlp, Tags, Notes)
VALUES (@t,@v,'analyst',@now,@now,75,'AMBER','threat-intel-tab','Added from Threat Intel tab')
"@ -SqlParameters @{ t=$type; v=$val; now=(Get-Date).ToString('o') }
        $TiStatusLbl.Text = "saved as $type IoC"
    } catch {
        $TiStatusLbl.Text = "save failed: $($_.Exception.Message)"
    }
}.GetNewClosure()
$TiAddIocBtn.Add_Click($tiAddIoc)

# ---- Runspace fan-out ---------------------------------------------------
# Each provider runs on its own runspace so the UI doesn't block on slow
# APIs (urlscan poll loop in particular). When a runspace finishes, its
# row is appended to the grid via Dispatcher.Invoke so WPF stays happy.
$tiPool = $null
$tiHandles = New-Object System.Collections.Generic.List[object]

# Provider plan lookup table - inlined here so the WPF closure has no
# cross-scope function dependency. Must match Get-IntelProviderPlan in
# Modules\SecIntel.ThreatIntel.ps1; if you add a provider, update both.
$tiPlanByType = @{
    'ip'      = @('abuseipdb')
    'ipv6'    = @('abuseipdb')
    'domain'  = @()
    'url'     = @('urlscan')
    'sha256'  = @('nsrl','virustotal','malwarebazaar','otx')
    'sha1'    = @('nsrl')
    'md5'     = @('nsrl')
    'product' = @('nist')
}

$tiLookup = {
    if ($tiPool) {
        try { $tiPool.Close(); $tiPool.Dispose() } catch {}
        $tiPool = $null
    }
    $tiResultList.Clear()
    $tiHandles.Clear()

    $val = $TiInputTxt.Text.Trim()
    if (-not $val) { return }

    $type = & $tiAutoDetect $val
    if (-not $type) {
        $TiTypeLbl.Text   = "type: unrecognised"
        $TiStatusLbl.Text = "could not auto-detect (try IPv4, domain, URL, MD5/SHA1/SHA256, or vendor:product)"
        return
    }
    $TiTypeLbl.Text = "type: $type"

    # Inline plan lookup - no cross-scope function calls.
    $providerNames = @()
    if ($tiPlanByType.ContainsKey($type)) { $providerNames = $tiPlanByType[$type] }
    if (-not $providerNames -or $providerNames.Count -eq 0) {
        $TiStatusLbl.Text = "no providers configured for type=$type"
        return
    }

    $TiStatusLbl.Text = "querying $($providerNames.Count) provider$(if ($providerNames.Count -ne 1){'s'}): " + ($providerNames -join ', ')

    # Build a fresh runspace pool for this lookup
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $tiPool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(2, $providerNames.Count), $iss, $Host)
    $tiPool.Open()

    foreach ($name in $providerNames) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $tiPool

        # Each runspace dot-sources the modules itself - it does not
        # inherit the parent session's loaded functions. Inside the
        # runspace, Get-IntelProviderPlan IS available because we just
        # dot-sourced it, so we use it to find the per-provider Run block.
        [void]$ps.AddScript({
            param($modulesDir, $value, $providerName, $iocType)
            . (Join-Path $modulesDir 'SecIntel.ThreatIntel.ps1')
            $plan = Get-IntelProviderPlan -IocType $iocType
            $entry = $plan | Where-Object Name -eq $providerName | Select-Object -First 1
            if (-not $entry) {
                return [PSCustomObject]@{
                    Source         = $providerName
                    Verdict        = 'unconfigured'
                    Family         = ''
                    DetectionRatio = "no provider entry for type=$iocType"
                    Reputation     = $null
                    Tags           = ''
                    ProviderUrl    = ''
                    FetchedAt      = (Get-Date).ToString('o')
                }
            }
            $result = $null
            $captured = $null
            try {
                # -ErrorAction Stop forces inner Write-Warning / silent returns to surface
                $result = & $entry.Run $value
            } catch {
                $captured = $_.Exception.Message
            }
            if ($result) {
                $result
            } elseif ($captured) {
                [PSCustomObject]@{
                    Source         = $providerName
                    Verdict        = 'error'
                    Family         = ''
                    DetectionRatio = $captured
                    Reputation     = $null
                    Tags           = ''
                    ProviderUrl    = ''
                    FetchedAt      = (Get-Date).ToString('o')
                }
            } else {
                # Provider ran but returned nothing - surface that visibly
                # so silent network failures or null returns are obvious.
                [PSCustomObject]@{
                    Source         = $providerName
                    Verdict        = 'no-data'
                    Family         = ''
                    DetectionRatio = 'provider returned no result (check transcript / network / API key)'
                    Reputation     = $null
                    Tags           = ''
                    ProviderUrl    = ''
                    FetchedAt      = (Get-Date).ToString('o')
                }
            }
        })
        [void]$ps.AddArgument($script:ModulesDir)
        [void]$ps.AddArgument($val)
        [void]$ps.AddArgument($name)
        [void]$ps.AddArgument($type)

        $async  = $ps.BeginInvoke()
        $tiHandles.Add(@{ Ps=$ps; Async=$async; Name=$name })
    }

    # Poll the handles on a DispatcherTimer so we update the UI
    # progressively rather than waiting for the slowest provider.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $timer.Add_Tick({
        $stillRunning = 0
        for ($i = $tiHandles.Count - 1; $i -ge 0; $i--) {
            $h = $tiHandles[$i]
            if ($h.Async.IsCompleted) {
                try {
                    $rows = $h.Ps.EndInvoke($h.Async)
                } catch {
                    $rows = $null
                    Write-Warning "$($h.Name) runspace failed: $($_.Exception.Message)"
                }
                $h.Ps.Dispose()
                $tiHandles.RemoveAt($i)
                foreach ($r in @($rows)) {
                    if (-not $r) { continue }
                    # Provider rows come back as either hashtables (saved
                    # to cache) or PSObjects from SQLite (cache hit). Both
                    # already share the same field names; just normalise.
                    $cachedAge = ''
                    try {
                        if ($r.FetchedAt) {
                            $age = ((Get-Date).ToUniversalTime() - [DateTime]::Parse($r.FetchedAt).ToUniversalTime()).TotalMinutes
                            $cachedAge = if ($age -lt 1) { 'fresh' }
                                         elseif ($age -lt 60) { "$([int]$age)m" }
                                         elseif ($age -lt 1440) { "$([int]($age/60))h" }
                                         else { "$([int]($age/1440))d" }
                        }
                    } catch {}
                    $tiResultList.Add([PSCustomObject]@{
                        Source         = [string]$r.Source
                        Verdict        = [string]$r.Verdict
                        Family         = [string]$r.Family
                        DetectionRatio = [string]$r.DetectionRatio
                        Reputation     = if ($null -ne $r.Reputation) { [string]$r.Reputation } else { '' }
                        Tags           = [string]$r.Tags
                        Cached         = $cachedAge
                        ProviderUrl    = [string]$r.ProviderUrl
                    })
                }
            } else {
                $stillRunning++
            }
        }
        if ($stillRunning -eq 0) {
            $this.Stop()
            $TiStatusLbl.Text = "$($tiResultList.Count) result$(if ($tiResultList.Count -ne 1){'s'}) - " + (Get-Date -Format 'HH:mm:ss')
            try { $tiPool.Close(); $tiPool.Dispose() } catch {}
            $tiPool = $null
        }
    })
    $timer.Start()
}.GetNewClosure()

$TiLookupBtn.Add_Click($tiLookup)
$TiInputTxt.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Return) {
        & $tiLookup
        $e.Handled = $true
    }
})

# Refresh provider configuration line on first build and whenever the
# tab is re-activated (so newly-set API keys reflect immediately).
& $updateProvidersLabel
$ThreatIntelTab.Tag = @{ Loader = $updateProvidersLabel }

# ============================================================
# KQL Builder
# ============================================================

# --- Common Sentinel / Defender / ADX tables and their full schemas (per CommonTableSchema.txt) ---
$kqlTables = [ordered]@{
    'SecurityEvent'         = @(
        'TenantId', 'TimeGenerated', 'SourceSystem', 'Account', 'AccountType', 'Computer', 'EventSourceName', 'Channel', 'Task', 'Level',
        'EventData', 'EventID', 'Activity', 'PartitionKey', 'RowKey', 'StorageAccount', 'AzureDeploymentID', 'AzureTableName',
        'AccessList', 'AccessMask', 'AccessReason', 'AccountDomain', 'AccountExpires', 'AccountName', 'AccountSessionIdentifier',
        'AdditionalInfo', 'AdditionalInfo2', 'AllowedToDelegateTo', 'Attributes', 'AuditPolicyChanges', 'AuditsDiscarded',
        'AuthenticationLevel', 'AuthenticationPackageName', 'AuthenticationProvider', 'AuthenticationServer', 'AuthenticationService',
        'AuthenticationType', 'CACertificateHash', 'CalledStationID', 'CallerProcessId', 'CallerProcessName', 'CallingStationID',
        'CAPublicKeyHash', 'CategoryId', 'CertificateDatabaseHash', 'ClassId', 'ClassName', 'ClientAddress', 'ClientIPAddress',
        'ClientName', 'CommandLine', 'CompatibleIds', 'DCDNSName', 'DeviceDescription', 'DeviceId', 'DisplayName', 'Disposition',
        'DomainBehaviorVersion', 'DomainName', 'DomainPolicyChanged', 'DomainSid', 'EAPType', 'ElevatedToken', 'ErrorCode',
        'ExtendedQuarantineState', 'FailureReason', 'FileHash', 'FilePath', 'FilePathNoUser', 'Filter', 'ForceLogoff', 'Fqbn',
        'FullyQualifiedSubjectMachineName', 'FullyQualifiedSubjectUserName', 'GroupMembership', 'HandleId', 'HardwareIds',
        'HomeDirectory', 'HomePath', 'ImpersonationLevel', 'InterfaceUuid', 'IpAddress', 'IpPort', 'KeyLength', 'LmPackageName',
        'LocationInformation', 'LockoutDuration', 'LockoutObservationWindow', 'LockoutThreshold', 'LoggingResult', 'LogonGuid',
        'LogonHours', 'LogonID', 'LogonProcessName', 'LogonType', 'LogonTypeName', 'MachineAccountQuota', 'MachineInventory',
        'MachineLogon', 'MandatoryLabel', 'MaxPasswordAge', 'MemberName', 'MemberSid', 'MinPasswordAge', 'MinPasswordLength',
        'MixedDomainMode', 'NASIdentifier', 'NASIPv4Address', 'NASIPv6Address', 'NASPort', 'NASPortType', 'NetworkPolicyName', 'NewDate',
        'NewMaxUsers', 'NewProcessId', 'NewProcessName', 'NewRemark', 'NewShareFlags', 'NewTime', 'NewUacValue', 'NewValue',
        'NewValueType', 'ObjectName', 'ObjectServer', 'ObjectType', 'ObjectValueName', 'OemInformation', 'OldMaxUsers', 'OldRemark',
        'OldShareFlags', 'OldUacValue', 'OldValue', 'OldValueType', 'OperationType', 'PackageName', 'ParentProcessName',
        'PasswordHistoryLength', 'PasswordLastSet', 'PasswordProperties', 'PreviousDate', 'PreviousTime', 'PrimaryGroupId',
        'PrivateKeyUsageCount', 'PrivilegeList', 'Process', 'ProcessId', 'ProcessName', 'Properties', 'ProfilePath', 'ProtocolSequence',
        'ProxyPolicyName', 'QuarantineHelpURL', 'QuarantineSessionID', 'QuarantineSessionIdentifier', 'QuarantineState',
        'QuarantineSystemHealthResult', 'RelativeTargetName', 'RemoteIpAddress', 'RemotePort', 'Requester', 'RequestId',
        'RestrictedAdminMode', 'RowsDeleted', 'SamAccountName', 'ScriptPath', 'SecurityDescriptor', 'ServiceAccount', 'ServiceFileName',
        'ServiceName', 'ServiceStartType', 'ServiceType', 'SessionName', 'ShareLocalPath', 'ShareName', 'SidHistory', 'Status',
        'SubjectAccount', 'SubcategoryGuid', 'SubcategoryId', 'Subject', 'SubjectDomainName', 'SubjectKeyIdentifier', 'SubjectLogonId',
        'SubjectMachineName', 'SubjectMachineSID', 'SubjectUserName', 'SubjectUserSid', 'SubStatus', 'TableId', 'TargetAccount',
        'TargetDomainName', 'TargetInfo', 'TargetLinkedLogonId', 'TargetLogonGuid', 'TargetLogonId', 'TargetOutboundDomainName',
        'TargetOutboundUserName', 'TargetServerName', 'TargetSid', 'TargetUser', 'TargetUserName', 'TargetUserSid', 'TemplateContent',
        'TemplateDSObjectFQDN', 'TemplateInternalName', 'TemplateOID', 'TemplateSchemaVersion', 'TemplateVersion', 'TokenElevationType',
        'TransmittedServices', 'UserAccountControl', 'UserParameters', 'UserPrincipalName', 'UserWorkstations', 'VirtualAccount',
        'VendorIds', 'Workstation', 'WorkstationName', 'EventLevelName', 'SourceComputerId', 'EventOriginId', 'MG', 'TimeCollected',
        'ManagementGroupName', 'SystemUserId', 'Version', 'Opcode', 'Keywords', 'Correlation', 'SystemProcessId', 'SystemThreadId',
        'EventRecordId', 'Type', '_ResourceId'
    )
    'Syslog'                = @(
        'TenantId', 'SourceSystem', 'TimeGenerated', 'MG', 'Computer', 'EventTime', 'Facility', 'HostName', 'SeverityLevel',
        'SyslogMessage', 'ProcessID', 'HostIP', 'ProcessName', 'CollectorHostName', 'Type', '_ResourceId'
    )
    'CommonSecurityLog'     = @(
        'TenantId', 'TimeGenerated', 'DeviceVendor', 'DeviceProduct', 'DeviceVersion', 'DeviceEventClassID', 'Activity', 'LogSeverity',
        'OriginalLogSeverity', 'AdditionalExtensions', 'DeviceAction', 'ApplicationProtocol', 'EventCount', 'DestinationDnsDomain',
        'DestinationServiceName', 'DestinationTranslatedAddress', 'DestinationTranslatedPort', 'CommunicationDirection',
        'DeviceDnsDomain', 'DeviceExternalID', 'DeviceFacility', 'DeviceInboundInterface', 'DeviceNtDomain', 'DeviceOutboundInterface',
        'DevicePayloadId', 'ProcessName', 'DeviceTranslatedAddress', 'DestinationHostName', 'DestinationMACAddress',
        'DestinationNTDomain', 'DestinationProcessId', 'DestinationUserPrivileges', 'DestinationProcessName', 'DestinationPort',
        'DestinationIP', 'DeviceTimeZone', 'DestinationUserID', 'DestinationUserName', 'DeviceAddress', 'DeviceName', 'DeviceMacAddress',
        'ProcessID', 'EndTime', 'ExternalID', 'ExtID', 'FileCreateTime', 'FileHash', 'FileID', 'FileModificationTime', 'FilePath',
        'FilePermission', 'FileType', 'FileName', 'FileSize', 'ReceivedBytes', 'Message', 'OldFileCreateTime', 'OldFileHash',
        'OldFileID', 'OldFileModificationTime', 'OldFileName', 'OldFilePath', 'OldFilePermission', 'OldFileSize', 'OldFileType',
        'SentBytes', 'EventOutcome', 'Protocol', 'Reason', 'RequestURL', 'RequestClientApplication', 'RequestContext', 'RequestCookies',
        'RequestMethod', 'ReceiptTime', 'SourceHostName', 'SourceMACAddress', 'SourceNTDomain', 'SourceDnsDomain', 'SourceServiceName',
        'SourceTranslatedAddress', 'SourceTranslatedPort', 'SourceProcessId', 'SourceUserPrivileges', 'SourceProcessName', 'SourcePort',
        'SourceIP', 'StartTime', 'SourceUserID', 'SourceUserName', 'EventType', 'DeviceEventCategory', 'DeviceCustomIPv6Address1',
        'DeviceCustomIPv6Address1Label', 'DeviceCustomIPv6Address2', 'DeviceCustomIPv6Address2Label', 'DeviceCustomIPv6Address3',
        'DeviceCustomIPv6Address3Label', 'DeviceCustomIPv6Address4', 'DeviceCustomIPv6Address4Label', 'DeviceCustomFloatingPoint1',
        'DeviceCustomFloatingPoint1Label', 'DeviceCustomFloatingPoint2', 'DeviceCustomFloatingPoint2Label', 'DeviceCustomFloatingPoint3',
        'DeviceCustomFloatingPoint3Label', 'DeviceCustomFloatingPoint4', 'DeviceCustomFloatingPoint4Label', 'DeviceCustomNumber1',
        'FieldDeviceCustomNumber1', 'DeviceCustomNumber1Label', 'DeviceCustomNumber2', 'FieldDeviceCustomNumber2',
        'DeviceCustomNumber2Label', 'DeviceCustomNumber3', 'FieldDeviceCustomNumber3', 'DeviceCustomNumber3Label', 'DeviceCustomString1',
        'DeviceCustomString1Label', 'DeviceCustomString2', 'DeviceCustomString2Label', 'DeviceCustomString3', 'DeviceCustomString3Label',
        'DeviceCustomString4', 'DeviceCustomString4Label', 'DeviceCustomString5', 'DeviceCustomString5Label', 'DeviceCustomString6',
        'DeviceCustomString6Label', 'DeviceCustomDate1', 'DeviceCustomDate1Label', 'DeviceCustomDate2', 'DeviceCustomDate2Label',
        'FlexDate1', 'FlexDate1Label', 'FlexNumber1', 'FlexNumber1Label', 'FlexNumber2', 'FlexNumber2Label', 'FlexString1',
        'FlexString1Label', 'FlexString2', 'FlexString2Label', 'RemoteIP', 'RemotePort', 'MaliciousIP', 'ThreatSeverity',
        'IndicatorThreatType', 'ThreatDescription', 'ThreatConfidence', 'ReportReferenceLink', 'MaliciousIPLongitude',
        'MaliciousIPLatitude', 'MaliciousIPCountry', 'Computer', 'SourceSystem', 'SimplifiedDeviceAction', 'CollectorHostName', 'Type',
        '_ResourceId'
    )
    'StorageFileLogs'       = @(
        'TenantId', 'TimeGenerated', 'AccountName', 'Location', 'Protocol', 'OperationName', 'AuthenticationType', 'StatusCode',
        'StatusText', 'DurationMs', 'ServerLatencyMs', 'Uri', 'CallerIpAddress', 'CorrelationId', 'SchemaVersion', 'OperationVersion',
        'AuthenticationHash', 'RequesterObjectId', 'RequesterTenantId', 'RequesterAppId', 'RequesterAudience', 'RequesterTokenIssuer',
        'RequesterUpn', 'RequesterUserName', 'AuthorizationDetails', 'SmbPrimarySID', 'UserAgentHeader', 'ReferrerHeader',
        'ClientRequestId', 'Etag', 'ServiceType', 'OperationCount', 'ObjectKey', 'RequestHeaderSize', 'RequestBodySize',
        'ResponseHeaderSize', 'ResponseBodySize', 'RequestMd5', 'ResponseMd5', 'LastModifiedTime', 'ConditionsUsed',
        'ContentLengthHeader', 'Category', 'TlsVersion', 'SmbTreeConnectID', 'SmbPersistentHandleID', 'SmbVolatileHandleID',
        'SmbMessageID', 'SmbCreditsConsumed', 'SmbCommandDetail', 'SmbFileId', 'SmbSessionID', 'SmbCommandMajor', 'SmbCommandMinor',
        'SasExpiryStatus', 'MetricResponseType', 'SmbStatusCode', 'SourceSystem', 'Type', '_ResourceId'
    )
    'BehaviorAnalytics'     = @(
        'TenantId', 'SourceRecordId', 'TimeGenerated', 'TimeProcessed', 'ActivityType', 'ActionType', 'UserName', 'UserPrincipalName',
        'EventSource', 'SourceIPAddress', 'SourceIPLocation', 'SourceDevice', 'DestinationIPAddress', 'DestinationIPLocation',
        'DestinationDevice', 'EventVendor', 'EventProductVersion', 'ActorName', 'ActorPrincipalName', 'TargetName',
        'TargetPrincipalName', 'Device', 'UsersInsights', 'DevicesInsights', 'ActivityInsights', 'SourceSystem', 'NativeTableName',
        'InvestigationPriority', 'Type', '_ResourceId'
    )
    'VMConnection'          = @(
        'TimeGenerated', 'Computer', 'Direction', 'ProcessName', 'SourceIp', 'DestinationIp', 'DestinationPort', 'Protocol', 'RemoteIp',
        'RemoteDnsQuestions', 'RemoteDnsCanonicalNames', 'RemoteClassification', 'RemoteLongitude', 'RemoteLatitude', 'RemoteCountry',
        'BytesSent', 'BytesReceived', 'LinksLive', 'LinksTerminated', 'LinksEstablished', 'LinksFailed', 'Responses', 'ResponseTimeSum',
        'ResponseTimeMin', 'ResponseTimeMax', 'MaliciousIp', 'IndicatorThreatType', 'Description', 'TLPLevel', 'Confidence', 'Severity',
        'FirstReportedDateTime', 'LastReportedDateTime', 'IsActive', 'ReportReferenceLink', 'AdditionalInformation', 'ConnectionId',
        'Machine', 'Process', 'AgentId', 'TenantId', 'SourceSystem', 'Type', '_ResourceId'
    )
    'W3CIISLog'             = @(
        'TenantId', 'SourceSystem', 'FileUri', 'FileOffset', 'StorageAccount', 'AzureDeploymentID', 'Role', 'RoleInstance', 'Date',
        'Time', 'TimeGenerated', 'sSiteName', 'sComputerName', 'sIP', 'csMethod', 'csUriStem', 'csUriQuery', 'sPort', 'csUserName',
        'cIP', 'csVersion', 'csUserAgent', 'csCookie', 'csReferer', 'csHost', 'scStatus', 'scSubStatus', 'scWin32Status', 'scBytes',
        'csBytes', 'TimeTaken', 'Computer', 'MaliciousIP', 'IndicatorThreatType', 'Description', 'TLPLevel', 'Confidence', 'Severity',
        'FirstReportedDateTime', 'LastReportedDateTime', 'IsActive', 'ReportReferenceLink', 'AdditionalInformation', 'RemoteIPLongitude',
        'RemoteIPLatitude', 'RemoteIPCountry', 'MG', 'ManagementGroupName', 'Type', '_ResourceId'
    )
    'DHCP'                  = @(
        'TimeGenerated', 'RawData', 'TenantId', 'Type', '_ResourceId', 'ID', 'Date', 'Time', 'Description', 'IP', 'HostName', 'MAC',
        'User', 'TransactionID', 'QResult', 'Probationtime', 'CorrelationID', 'DhcidVendorClass', 'VendorClass', 'UserClassHex',
        'UserClassASCII', 'RelayAgentInformation', 'DnsRegError'
    )
    'DeviceEvents'          = @(
        'TenantId', 'AccountDomain', 'AccountName', 'AccountSid', 'ActionType', 'AdditionalFields', 'AppGuardContainerId', 'DeviceId',
        'DeviceName', 'FileName', 'FileOriginIP', 'FileOriginUrl', 'FolderPath', 'InitiatingProcessAccountDomain',
        'InitiatingProcessAccountName', 'InitiatingProcessAccountObjectId', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
        'InitiatingProcessCommandLine', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId',
        'InitiatingProcessLogonId', 'InitiatingProcessMD5', 'InitiatingProcessParentFileName', 'InitiatingProcessParentId',
        'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'LocalIP', 'LocalPort', 'LogonId', 'MD5', 'MachineGroup',
        'ProcessCommandLine', 'ProcessId', 'ProcessTokenElevation', 'RegistryKey', 'RegistryValueData', 'RegistryValueName',
        'RemoteDeviceName', 'RemoteIP', 'RemotePort', 'RemoteUrl', 'ReportId', 'SHA1', 'SHA256', 'Timestamp', 'TimeGenerated',
        'FileSize', 'InitiatingProcessCreationTime', 'InitiatingProcessFileSize', 'InitiatingProcessParentCreationTime',
        'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoFileDescription',
        'InitiatingProcessVersionInfoInternalFileName', 'InitiatingProcessVersionInfoOriginalFileName',
        'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion', 'ProcessCreationTime',
        'CreatedProcessSessionId', 'IsProcessRemoteSession', 'ProcessRemoteSessionDeviceName', 'ProcessRemoteSessionIP',
        'InitiatingProcessSessionId', 'IsInitiatingProcessRemoteSession', 'InitiatingProcessRemoteSessionDeviceName',
        'InitiatingProcessRemoteSessionIP', 'InitiatingProcessUniqueId', 'SourceSystem', 'Type'
    )
    'DeviceRegistryEvents'  = @(
        'TenantId', 'ActionType', 'AppGuardContainerId', 'DeviceId', 'DeviceName', 'InitiatingProcessAccountDomain',
        'InitiatingProcessAccountName', 'InitiatingProcessAccountObjectId', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
        'InitiatingProcessCommandLine', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId',
        'InitiatingProcessIntegrityLevel', 'InitiatingProcessMD5', 'InitiatingProcessParentFileName', 'InitiatingProcessParentId',
        'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'InitiatingProcessTokenElevation', 'InitiatingProcessFileSize',
        'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
        'InitiatingProcessVersionInfoProductVersion', 'InitiatingProcessVersionInfoInternalFileName',
        'InitiatingProcessVersionInfoOriginalFileName', 'InitiatingProcessVersionInfoFileDescription', 'MachineGroup',
        'PreviousRegistryKey', 'PreviousRegistryValueData', 'PreviousRegistryValueName', 'RegistryKey', 'RegistryValueData',
        'RegistryValueName', 'RegistryValueType', 'ReportId', 'TimeGenerated', 'Timestamp', 'InitiatingProcessParentCreationTime',
        'InitiatingProcessCreationTime', 'InitiatingProcessSessionId', 'IsInitiatingProcessRemoteSession',
        'InitiatingProcessRemoteSessionDeviceName', 'InitiatingProcessRemoteSessionIP', 'InitiatingProcessUniqueId', 'SourceSystem',
        'Type'
    )
    'DeviceFileEvents'      = @(
        'TenantId', 'ActionType', 'AdditionalFields', 'AppGuardContainerId', 'DeviceId', 'DeviceName', 'FileName', 'FileOriginIP',
        'FileOriginReferrerUrl', 'FileOriginUrl', 'FileSize', 'FolderPath', 'InitiatingProcessAccountDomain',
        'InitiatingProcessAccountName', 'InitiatingProcessAccountObjectId', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
        'InitiatingProcessCommandLine', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId',
        'InitiatingProcessIntegrityLevel', 'InitiatingProcessMD5', 'InitiatingProcessParentFileName', 'InitiatingProcessParentId',
        'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'InitiatingProcessTokenElevation', 'IsAzureInfoProtectionApplied', 'MD5',
        'MachineGroup', 'PreviousFileName', 'PreviousFolderPath', 'ReportId', 'RequestAccountDomain', 'RequestAccountName',
        'RequestAccountSid', 'RequestProtocol', 'RequestSourceIP', 'RequestSourcePort', 'SHA1', 'SHA256', 'SensitivityLabel',
        'SensitivitySubLabel', 'ShareName', 'Timestamp', 'TimeGenerated', 'InitiatingProcessParentCreationTime',
        'InitiatingProcessCreationTime', 'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
        'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessVersionInfoInternalFileName',
        'InitiatingProcessVersionInfoOriginalFileName', 'InitiatingProcessVersionInfoProductName',
        'InitiatingProcessVersionInfoProductVersion', 'InitiatingProcessSessionId', 'IsInitiatingProcessRemoteSession',
        'InitiatingProcessRemoteSessionDeviceName', 'InitiatingProcessRemoteSessionIP', 'InitiatingProcessUniqueId', 'SourceSystem',
        'Type'
    )
    'DeviceProcessEvents'   = @(
        'TenantId', 'AccountDomain', 'AccountName', 'AccountObjectId', 'AccountSid', 'AccountUpn', 'ActionType', 'AdditionalFields',
        'AppGuardContainerId', 'DeviceId', 'DeviceName', 'FileName', 'FolderPath', 'FileSize', 'InitiatingProcessAccountDomain',
        'InitiatingProcessAccountName', 'InitiatingProcessAccountObjectId', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
        'InitiatingProcessCommandLine', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId',
        'InitiatingProcessIntegrityLevel', 'InitiatingProcessLogonId', 'InitiatingProcessMD5', 'InitiatingProcessParentFileName',
        'InitiatingProcessParentId', 'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'InitiatingProcessTokenElevation',
        'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
        'InitiatingProcessVersionInfoProductVersion', 'InitiatingProcessVersionInfoInternalFileName',
        'InitiatingProcessVersionInfoOriginalFileName', 'InitiatingProcessVersionInfoFileDescription', 'LogonId', 'MD5', 'MachineGroup',
        'ProcessCommandLine', 'ProcessCreationTime', 'ProcessId', 'ProcessIntegrityLevel', 'ProcessTokenElevation',
        'ProcessVersionInfoCompanyName', 'ProcessVersionInfoProductName', 'ProcessVersionInfoProductVersion',
        'ProcessVersionInfoInternalFileName', 'ProcessVersionInfoOriginalFileName', 'ProcessVersionInfoFileDescription',
        'InitiatingProcessSignerType', 'InitiatingProcessSignatureStatus', 'ReportId', 'SHA1', 'SHA256', 'TimeGenerated', 'Timestamp',
        'InitiatingProcessParentCreationTime', 'InitiatingProcessCreationTime', 'CreatedProcessSessionId', 'IsProcessRemoteSession',
        'ProcessRemoteSessionDeviceName', 'ProcessRemoteSessionIP', 'InitiatingProcessSessionId', 'IsInitiatingProcessRemoteSession',
        'InitiatingProcessRemoteSessionDeviceName', 'InitiatingProcessRemoteSessionIP', 'InitiatingProcessUniqueId', 'ProcessUniqueId',
        'SourceSystem', 'Type'
    )
    'DeviceNetworkEvents'   = @(
        'TenantId', 'ActionType', 'AdditionalFields', 'AppGuardContainerId', 'DeviceId', 'DeviceName', 'InitiatingProcessAccountDomain',
        'InitiatingProcessAccountName', 'InitiatingProcessAccountObjectId', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
        'InitiatingProcessCommandLine', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId',
        'InitiatingProcessIntegrityLevel', 'InitiatingProcessMD5', 'InitiatingProcessParentFileName', 'InitiatingProcessParentId',
        'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'InitiatingProcessTokenElevation', 'InitiatingProcessFileSize',
        'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
        'InitiatingProcessVersionInfoProductVersion', 'InitiatingProcessVersionInfoInternalFileName',
        'InitiatingProcessVersionInfoOriginalFileName', 'InitiatingProcessVersionInfoFileDescription', 'LocalIP', 'LocalIPType',
        'LocalPort', 'MachineGroup', 'Protocol', 'RemoteIP', 'RemoteIPType', 'RemotePort', 'RemoteUrl', 'ReportId', 'TimeGenerated',
        'Timestamp', 'InitiatingProcessParentCreationTime', 'InitiatingProcessCreationTime', 'InitiatingProcessSessionId',
        'IsInitiatingProcessRemoteSession', 'InitiatingProcessRemoteSessionDeviceName', 'InitiatingProcessRemoteSessionIP',
        'InitiatingProcessUniqueId', 'SourceSystem', 'Type'
    )
    'TomcatEvent'           = @(
        'TimeGenerated', 'EventProduct', 'EventType', 'EventSeverity', 'EventStartTime', 'SrcIpAddr', 'ClientIdentity', 'SrcUserName',
        'HttpRequestMethod', 'UrlOriginal', 'HttpVersion', 'HttpStatusCode', 'HttpResponseBodyBytes', 'HttpReferrerOriginal',
        'HttpUserAgentOriginal', 'ClassName', 'DvcAction', 'EventMessage', 'ServerHostName'
    )
    'DeviceImageLoadEvents' = @(
        'TenantId', 'ActionType', 'AppGuardContainerId', 'DeviceId', 'DeviceName', 'FileName', 'FolderPath',
        'InitiatingProcessAccountDomain', 'InitiatingProcessAccountName', 'InitiatingProcessAccountObjectId',
        'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn', 'InitiatingProcessCommandLine', 'InitiatingProcessFileName',
        'InitiatingProcessFolderPath', 'InitiatingProcessId', 'InitiatingProcessIntegrityLevel', 'InitiatingProcessMD5',
        'InitiatingProcessParentFileName', 'InitiatingProcessParentId', 'InitiatingProcessSHA1', 'InitiatingProcessSHA256',
        'InitiatingProcessTokenElevation', 'MD5', 'MachineGroup', 'ReportId', 'SHA1', 'SHA256', 'Timestamp', 'TimeGenerated',
        'InitiatingProcessParentCreationTime', 'InitiatingProcessCreationTime', 'InitiatingProcessFileSize',
        'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoFileDescription',
        'InitiatingProcessVersionInfoInternalFileName', 'InitiatingProcessVersionInfoOriginalFileName',
        'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion', 'FileSize',
        'InitiatingProcessSessionId', 'IsInitiatingProcessRemoteSession', 'InitiatingProcessRemoteSessionDeviceName',
        'InitiatingProcessRemoteSessionIP', 'InitiatingProcessUniqueId', 'SourceSystem', 'Type'
    )
    'DeviceNetworkInfo'     = @(
        'TenantId', 'ConnectedNetworks', 'DefaultGateways', 'DeviceId', 'DeviceName', 'DnsAddresses', 'IPAddresses', 'IPv4Dhcp',
        'IPv6Dhcp', 'MacAddress', 'MachineGroup', 'NetworkAdapterName', 'NetworkAdapterStatus', 'NetworkAdapterType', 'ReportId',
        'TimeGenerated', 'Timestamp', 'TunnelType', 'NetworkAdapterVendor', 'SourceSystem', 'Type'
    )
    'DeviceLogonEvents'     = @(
        'TenantId', 'AccountDomain', 'AccountName', 'AccountSid', 'ActionType', 'AdditionalFields', 'AppGuardContainerId', 'DeviceId',
        'DeviceName', 'FailureReason', 'InitiatingProcessAccountDomain', 'InitiatingProcessAccountName',
        'InitiatingProcessAccountObjectId', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn', 'InitiatingProcessCommandLine',
        'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId', 'InitiatingProcessIntegrityLevel',
        'InitiatingProcessMD5', 'InitiatingProcessParentFileName', 'InitiatingProcessParentId', 'InitiatingProcessSHA1',
        'InitiatingProcessSHA256', 'InitiatingProcessTokenElevation', 'IsLocalAdmin', 'LogonId', 'LogonType', 'MachineGroup', 'Protocol',
        'RemoteDeviceName', 'RemoteIP', 'RemoteIPType', 'RemotePort', 'ReportId', 'Timestamp', 'TimeGenerated',
        'InitiatingProcessParentCreationTime', 'InitiatingProcessCreationTime', 'InitiatingProcessFileSize',
        'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoFileDescription',
        'InitiatingProcessVersionInfoInternalFileName', 'InitiatingProcessVersionInfoOriginalFileName',
        'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion', 'InitiatingProcessSessionId',
        'IsInitiatingProcessRemoteSession', 'InitiatingProcessRemoteSessionDeviceName', 'InitiatingProcessRemoteSessionIP',
        'InitiatingProcessUniqueId', 'SourceSystem', 'Type'
    )
    'SigninLogs'            = @(
        'TenantId', 'SourceSystem', 'TimeGenerated', 'ResourceId', 'OperationName', 'OperationVersion', 'Category', 'ResultType',
        'ResultSignature', 'ResultDescription', 'DurationMs', 'CorrelationId', 'Resource', 'ResourceGroup', 'ResourceProvider',
        'Identity', 'Level', 'Location', 'AlternateSignInName', 'AppDisplayName', 'AppId', 'AuthenticationContextClassReferences',
        'AuthenticationDetails', 'AppliedEventListeners', 'AuthenticationMethodsUsed', 'AuthenticationProcessingDetails',
        'AuthenticationRequirement', 'AuthenticationRequirementPolicies', 'ClientAppUsed', 'ConditionalAccessPolicies',
        'ConditionalAccessStatus', 'CreatedDateTime', 'DeviceDetail', 'IsInteractive', 'Id', 'IPAddress', 'IsRisky', 'LocationDetails',
        'MfaDetail', 'NetworkLocationDetails', 'OriginalRequestId', 'ProcessingTimeInMilliseconds', 'RiskDetail', 'RiskEventTypes',
        'RiskEventTypes_V2', 'RiskLevelAggregated', 'RiskLevelDuringSignIn', 'RiskState', 'ResourceDisplayName', 'ResourceIdentity',
        'ResourceServicePrincipalId', 'ServicePrincipalId', 'ServicePrincipalName', 'Status', 'TokenIssuerName', 'TokenIssuerType',
        'UserAgent', 'UserDisplayName', 'UserId', 'UserPrincipalName', 'AADTenantId', 'UserType', 'FlaggedForReview',
        'IPAddressFromResourceProvider', 'SignInIdentifier', 'SignInIdentifierType', 'ResourceTenantId', 'HomeTenantId',
        'UniqueTokenIdentifier', 'SessionId', 'SessionLifetimePolicies', 'AutonomousSystemNumber', 'AuthenticationProtocol',
        'CrossTenantAccessType', 'AuthenticationAppDeviceDetails', 'AuthenticationAppPolicyEvaluationDetails', 'ClientCredentialType',
        'FederatedCredentialId', 'GlobalSecureAccessIpAddress', 'HomeTenantName', 'IncomingTokenType', 'IsTenantRestricted',
        'IsThroughGlobalSecureAccess', 'OriginalTransferMethod', 'TokenProtectionStatusDetails', 'AppOwnerTenantId',
        'ResourceOwnerTenantId', 'Agent', 'SourceAppClientId', 'AppliedConditionalAccessPolicies', 'RiskLevel', 'Type'
    )
    'AuditLogs'             = @(
        'TenantId', 'SourceSystem', 'TimeGenerated', 'ResourceId', 'OperationName', 'OperationVersion', 'Category', 'ResultType',
        'ResultSignature', 'ResultDescription', 'DurationMs', 'CorrelationId', 'Resource', 'ResourceGroup', 'ResourceProvider',
        'Identity', 'Level', 'Location', 'AdditionalDetails', 'Id', 'InitiatedBy', 'LoggedByService', 'Result', 'ResultReason',
        'TargetResources', 'AADTenantId', 'ActivityDisplayName', 'ActivityDateTime', 'AADOperationType', 'Type'
    )
    'SecurityIncident'      = @(
        'TenantId', 'TimeGenerated', 'IncidentName', 'Title', 'Description', 'Severity', 'Status', 'Classification',
        'ClassificationComment', 'ClassificationReason', 'Owner', 'ProviderName', 'ProviderIncidentId', 'FirstActivityTime',
        'LastActivityTime', 'FirstModifiedTime', 'LastModifiedTime', 'CreatedTime', 'ClosedTime', 'IncidentNumber',
        'RelatedAnalyticRuleIds', 'AlertIds', 'BookmarkIds', 'Comments', 'Tasks', 'Labels', 'IncidentUrl', 'AdditionalData',
        'ModifiedBy', 'SourceSystem', 'Type'
    )
    'SecurityAlert'         = @(
        'TenantId', 'TimeGenerated', 'DisplayName', 'AlertName', 'AlertSeverity', 'Description', 'ProviderName', 'VendorName',
        'VendorOriginalId', 'SystemAlertId', 'ResourceId', 'SourceComputerId', 'AlertType', 'ConfidenceLevel', 'ConfidenceScore',
        'IsIncident', 'StartTime', 'EndTime', 'ProcessingEndTime', 'RemediationSteps', 'ExtendedProperties', 'Entities', 'SourceSystem',
        'WorkspaceSubscriptionId', 'WorkspaceResourceGroup', 'ExtendedLinks', 'ProductName', 'ProductComponentName', 'AlertLink',
        'Status', 'CompromisedEntity', 'Tactics', 'Techniques', 'SubTechniques', 'Type'
    )
    'Anomalies'             = @(
        'TenantId', 'Id', 'WorkspaceId', 'VendorName', 'TimeGenerated', 'AnomalyTemplateId', 'AnomalyTemplateName',
        'AnomalyTemplateVersion', 'RuleId', 'RuleStatus', 'RuleName', 'RuleConfigVersion', 'Score', 'Description', 'StartTime',
        'EndTime', 'ExtendedLinks', 'Tactics', 'Techniques', 'UserName', 'UserPrincipalName', 'SourceIpAddress', 'SourceLocation',
        'SourceDevice', 'DestinationIpAddress', 'DestinationLocation', 'DestinationDevice', 'ActivityInsights', 'DeviceInsights',
        'UserInsights', 'AnomalyReasons', 'Entities', 'ExtendedProperties', 'AnomalyDetails', 'SourceSystem', 'Type'
    )
}

$kqlOperators       = @('==','!=','=~','!~','>','<','>=','<=','contains','!contains','contains_cs','has','!has','has_cs','startswith','!startswith','endswith','!endswith','in','!in','in~','!in~','matches regex','between')
$kqlTimeRanges      = @('Last 30m','Last 1h','Last 4h','Last 24h','Last 7d','Last 30d','Last 90d','Custom...')
$kqlBinTimes        = @('No binning','1m','5m','15m','30m','1h','6h','12h','1d')
$kqlAggFuncs        = @('count()','countif({col} != "")','dcount({col})','dcountif({col}, true)','sum({col})','avg({col})','min({col})','max({col})','percentile({col}, 50)','percentile({col}, 95)','percentile({col}, 99)','make_set({col})','make_list({col})','arg_min({col}, *)','arg_max({col}, *)','take_any({col})','stdev({col})','variance({col})')
$kqlOrderDirections = @('desc','asc')
$kqlTakeModes       = @('take (any N)','top N by order')

# --- Templates: curated hunting query collection from KqlTemplates.ps1 ---
# This module file holds the full ~1900-line template library (Mega Query
# framework rev 3.0.0 + 3.0.1, per-tactic subqueries, APT-Hunt-CN-RU,
# InitialAccess-Anomaly, hunting-pack §1-§3). Edit it directly to add or
# tweak templates without touching the dashboard.
. (Join-Path $script:ModulesDir 'KqlTemplates.ps1')

# --- Populate static dropdowns ---
$KqlTableCombo.ItemsSource    = @($kqlTables.Keys)
$KqlTimeCombo.ItemsSource     = $kqlTimeRanges
$KqlTimeCombo.SelectedIndex   = 3                          # Last 24h
$KqlBinTimeCombo.ItemsSource  = $kqlBinTimes
$KqlBinTimeCombo.SelectedIndex= 0                          # No binning
$KqlOrderDirCombo.ItemsSource = $kqlOrderDirections
$KqlOrderDirCombo.SelectedIndex = 0                        # desc
$KqlTakeMode.ItemsSource      = $kqlTakeModes
$KqlTakeMode.SelectedIndex    = 0                          # take

# Populate templates list
foreach ($k in $kqlTemplates.Keys) {
    $li = New-Object System.Windows.Controls.ListBoxItem
    $li.Content = $k
    $li.Tag     = $kqlTemplates[$k]
    [void]$KqlTemplatesList.Items.Add($li)
}

# State: columns of the currently-selected table
$script:KqlCurrentColumns = @()

# --- Build-query closure: emits the canonical pipeline ---
$buildKqlQuery = {
    try {
        $sb = New-Object System.Text.StringBuilder

        $table = $KqlTableCombo.Text
        if (-not $table) {
            $KqlOutputTxt.Text         = "// Select a table to begin"
            $KqlOutputStatusLbl.Text   = ""
            return
        }
        [void]$sb.AppendLine($table)

        # 1. Time filter (always emitted before user filters - "filter early")
        $tr = if ($KqlTimeCombo.SelectedItem) { $KqlTimeCombo.SelectedItem.ToString() } else { '' }
        if ($tr -and $tr -ne 'Custom...') {
            $ago = ($tr -replace '^Last\s+', '').ToLower()
            [void]$sb.AppendLine("| where TimeGenerated > ago($ago)")
        } elseif ($tr -eq 'Custom...' -and $KqlCustomTimeTxt.Text) {
            [void]$sb.AppendLine("| where TimeGenerated $($KqlCustomTimeTxt.Text)")
        }

        # 2. User filters (chained with AND)
        foreach ($row in $KqlFiltersStack.Children) {
            $col = $row.Tag.ColumnControl.Text
            $op  = if ($row.Tag.OperatorControl.SelectedItem) { $row.Tag.OperatorControl.SelectedItem.ToString() } else { $row.Tag.OperatorControl.Text }
            $val = $row.Tag.ValueControl.Text
            if (-not $col -or -not $op) { continue }

            $needsQuote = $true
            if ($val -match '^-?\d+(\.\d+)?$')                             { $needsQuote = $false }
            elseif ($val -match '^(true|false)$')                          { $needsQuote = $false }
            elseif ($val -match '^(datetime|ago|bin|now|startofday|endofday|dynamic|todynamic|todatetime|toint|tolong|todouble|tostring|parse_json)\(') { $needsQuote = $false }
            elseif ($val.StartsWith('(') -and $val.EndsWith(')'))          { $needsQuote = $false }
            elseif ($op -in 'in','!in','in~','!in~') {
                if ($val -notmatch '^\(') { $val = "($val)" }
                $needsQuote = $false
            }
            elseif ($op -eq 'between')                                      { $needsQuote = $false }

            if ($needsQuote) { $val = '"' + $val + '"' }
            [void]$sb.AppendLine("| where $col $op $val")
        }

        # 3. Extend (computed columns)
        foreach ($row in $KqlExtendStack.Children) {
            $name = $row.Tag.NameControl.Text
            $expr = $row.Tag.ExprControl.Text
            if (-not $name -or -not $expr) { continue }
            [void]$sb.AppendLine("| extend $name = $expr")
        }

        # 4. Project / project-away
        $checkedCols = @()
        foreach ($child in $KqlProjectList.Items) {
            if ($child -is [System.Windows.Controls.CheckBox] -and $child.IsChecked) {
                $checkedCols += $child.Tag
            }
        }
        if ($checkedCols.Count -gt 0) {
            $verb = if ($KqlProjectMode_ProjectAway.IsChecked) { 'project-away' } else { 'project' }
            [void]$sb.AppendLine("| $verb $($checkedCols -join ', ')")
        }

        # 5. Summarize
        $aggExprs = @()
        foreach ($row in $KqlAggStack.Children) {
            $func  = if ($row.Tag.FuncControl.SelectedItem) { $row.Tag.FuncControl.SelectedItem.ToString() } else { $row.Tag.FuncControl.Text }
            $col   = $row.Tag.ColControl.Text
            $alias = $row.Tag.AliasControl.Text
            if (-not $func) { continue }
            $expr = $func -replace '\{col\}', $col
            if ($alias) { $expr = "$alias = $expr" }
            $aggExprs += $expr
        }
        if ($aggExprs.Count -gt 0) {
            $byParts = @()
            $bin = if ($KqlBinTimeCombo.SelectedItem) { $KqlBinTimeCombo.SelectedItem.ToString() } else { 'No binning' }
            if ($bin -ne 'No binning') { $byParts += "bin(TimeGenerated, $bin)" }
            if ($KqlGroupByTxt.Text)   { $byParts += $KqlGroupByTxt.Text }
            $line = "| summarize " + ($aggExprs -join ', ')
            if ($byParts.Count -gt 0)  { $line += " by " + ($byParts -join ', ') }
            [void]$sb.AppendLine($line)
        }

        # 6. Order by + take/top
        $emitTake  = $true
        $orderCol  = $KqlOrderColCombo.Text
        $dir       = if ($KqlOrderDirCombo.SelectedItem) { $KqlOrderDirCombo.SelectedItem.ToString() } else { 'desc' }
        $takeMode  = if ($KqlTakeMode.SelectedItem) { $KqlTakeMode.SelectedItem.ToString() } else { 'take (any N)' }
        $n         = $KqlTakeTxt.Text

        if ($orderCol) {
            if ($takeMode -like 'top*' -and $n -match '^\d+$') {
                [void]$sb.AppendLine("| top $n by $orderCol $dir")
                $emitTake = $false
            } else {
                [void]$sb.AppendLine("| order by $orderCol $dir")
            }
        }
        if ($emitTake -and $n -match '^\d+$') {
            [void]$sb.AppendLine("| take $n")
        }

        $text = $sb.ToString().TrimEnd()
        $KqlOutputTxt.Text       = $text
        $KqlOutputStatusLbl.Text = "$($text.Split([char]10).Count) lines  built " + (Get-Date).ToString('HH:mm:ss')
    } catch {
        $KqlOutputStatusLbl.Text = "Build error: $($_.Exception.Message)"
    }
}

# --- Helper: rebuild the project/order column lists when the table changes ---
$updateKqlColumns = {
    $tableName = $KqlTableCombo.Text
    $cols = if ($kqlTables.Contains($tableName)) { $kqlTables[$tableName] } else { @('TimeGenerated') }
    $script:KqlCurrentColumns = $cols

    # Refresh project list (CheckBoxes)
    $KqlProjectList.Items.Clear()
    foreach ($c in $cols) {
        $cb               = New-Object System.Windows.Controls.CheckBox
        $cb.Content       = $c
        $cb.Tag           = $c
        $cb.Margin        = New-Object System.Windows.Thickness(14,4,14,4)
        $cb.Foreground    = $window.FindResource('FgBrush')
        $cb.Add_Click({ & $buildKqlQuery }.GetNewClosure())
        [void]$KqlProjectList.Items.Add($cb)
    }
    # Refresh order-by combo
    $KqlOrderColCombo.ItemsSource = $cols
    # Refresh column ItemsSource on every existing filter/extend/agg row
    foreach ($r in $KqlFiltersStack.Children) { if ($r.Tag.ColumnControl) { $r.Tag.ColumnControl.ItemsSource = $cols } }
    foreach ($r in $KqlAggStack.Children)     { if ($r.Tag.ColControl)    { $r.Tag.ColControl.ItemsSource    = $cols } }
}

# --- Factory: filter row (column / operator / value / remove) ---
$addKqlFilterRow = {
    $row = New-Object System.Windows.Controls.Grid
    $row.Margin = New-Object System.Windows.Thickness(0,0,0,6)
    $cdef1 = New-Object System.Windows.Controls.ColumnDefinition; $cdef1.Width = New-Object System.Windows.GridLength(2, 'Star'); [void]$row.ColumnDefinitions.Add($cdef1)
    $cdef2 = New-Object System.Windows.Controls.ColumnDefinition; $cdef2.Width = '160';                                          [void]$row.ColumnDefinitions.Add($cdef2)
    $cdef3 = New-Object System.Windows.Controls.ColumnDefinition; $cdef3.Width = New-Object System.Windows.GridLength(3, 'Star'); [void]$row.ColumnDefinitions.Add($cdef3)
    $cdef4 = New-Object System.Windows.Controls.ColumnDefinition; $cdef4.Width = 'Auto';                                          [void]$row.ColumnDefinitions.Add($cdef4)

    $colCombo = New-Object System.Windows.Controls.ComboBox
    $colCombo.IsEditable = $true
    $colCombo.Margin     = New-Object System.Windows.Thickness(0,0,8,0)
    $colCombo.ItemsSource= $script:KqlCurrentColumns
    [System.Windows.Controls.Grid]::SetColumn($colCombo, 0)

    $opCombo = New-Object System.Windows.Controls.ComboBox
    $opCombo.ItemsSource = $kqlOperators
    $opCombo.SelectedIndex = 0
    $opCombo.Margin      = New-Object System.Windows.Thickness(0,0,8,0)
    [System.Windows.Controls.Grid]::SetColumn($opCombo, 1)

    $valTxt = New-Object System.Windows.Controls.TextBox
    $valTxt.Margin = New-Object System.Windows.Thickness(0,0,8,0)
    [System.Windows.Controls.Grid]::SetColumn($valTxt, 2)

    $rmBtn = New-Object System.Windows.Controls.Button
    $rmBtn.Content = 'X'
    $rmBtn.Width = 30
    $rmBtn.Add_Click({ $KqlFiltersStack.Children.Remove($row); & $buildKqlQuery }.GetNewClosure())
    [System.Windows.Controls.Grid]::SetColumn($rmBtn, 3)

    [void]$row.Children.Add($colCombo)
    [void]$row.Children.Add($opCombo)
    [void]$row.Children.Add($valTxt)
    [void]$row.Children.Add($rmBtn)
    $row.Tag = @{ ColumnControl = $colCombo; OperatorControl = $opCombo; ValueControl = $valTxt }

    $colCombo.Add_LostFocus({ & $buildKqlQuery }.GetNewClosure())
    $opCombo.Add_SelectionChanged({ & $buildKqlQuery }.GetNewClosure())
    $valTxt.Add_LostFocus({ & $buildKqlQuery }.GetNewClosure())

    [void]$KqlFiltersStack.Children.Add($row)
    & $buildKqlQuery
}

# --- Factory: extend row (name / expression / remove) ---
$addKqlExtendRow = {
    $row = New-Object System.Windows.Controls.Grid
    $row.Margin = New-Object System.Windows.Thickness(0,0,0,6)
    $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = New-Object System.Windows.GridLength(1, 'Star'); [void]$row.ColumnDefinitions.Add($c1)
    $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = New-Object System.Windows.GridLength(3, 'Star'); [void]$row.ColumnDefinitions.Add($c2)
    $c3 = New-Object System.Windows.Controls.ColumnDefinition; $c3.Width = 'Auto';                                            [void]$row.ColumnDefinitions.Add($c3)

    $nameTxt = New-Object System.Windows.Controls.TextBox
    $nameTxt.Margin = New-Object System.Windows.Thickness(0,0,8,0)
    $nameTxt.ToolTip = 'Column name'
    [System.Windows.Controls.Grid]::SetColumn($nameTxt, 0)

    $exprTxt = New-Object System.Windows.Controls.TextBox
    $exprTxt.Margin = New-Object System.Windows.Thickness(0,0,8,0)
    $exprTxt.ToolTip = 'KQL expression, e.g. hourofday(TimeGenerated)'
    [System.Windows.Controls.Grid]::SetColumn($exprTxt, 1)

    $rmBtn = New-Object System.Windows.Controls.Button
    $rmBtn.Content = 'X'
    $rmBtn.Width = 30
    $rmBtn.Add_Click({ $KqlExtendStack.Children.Remove($row); & $buildKqlQuery }.GetNewClosure())
    [System.Windows.Controls.Grid]::SetColumn($rmBtn, 2)

    [void]$row.Children.Add($nameTxt)
    [void]$row.Children.Add($exprTxt)
    [void]$row.Children.Add($rmBtn)
    $row.Tag = @{ NameControl = $nameTxt; ExprControl = $exprTxt }

    $nameTxt.Add_LostFocus({ & $buildKqlQuery }.GetNewClosure())
    $exprTxt.Add_LostFocus({ & $buildKqlQuery }.GetNewClosure())

    [void]$KqlExtendStack.Children.Add($row)
    & $buildKqlQuery
}

# --- Factory: aggregation row (function / column / alias / remove) ---
$addKqlAggRow = {
    $row = New-Object System.Windows.Controls.Grid
    $row.Margin = New-Object System.Windows.Thickness(0,0,0,6)
    $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = New-Object System.Windows.GridLength(2, 'Star'); [void]$row.ColumnDefinitions.Add($c1)
    $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = New-Object System.Windows.GridLength(2, 'Star'); [void]$row.ColumnDefinitions.Add($c2)
    $c3 = New-Object System.Windows.Controls.ColumnDefinition; $c3.Width = New-Object System.Windows.GridLength(1, 'Star'); [void]$row.ColumnDefinitions.Add($c3)
    $c4 = New-Object System.Windows.Controls.ColumnDefinition; $c4.Width = 'Auto';                                            [void]$row.ColumnDefinitions.Add($c4)

    $funcCombo = New-Object System.Windows.Controls.ComboBox
    $funcCombo.IsEditable = $true
    $funcCombo.ItemsSource = $kqlAggFuncs
    $funcCombo.SelectedIndex = 0
    $funcCombo.Margin = New-Object System.Windows.Thickness(0,0,8,0)
    $funcCombo.ToolTip = '{col} placeholder is replaced with the column name on the right'
    [System.Windows.Controls.Grid]::SetColumn($funcCombo, 0)

    $colCombo = New-Object System.Windows.Controls.ComboBox
    $colCombo.IsEditable = $true
    $colCombo.ItemsSource = $script:KqlCurrentColumns
    $colCombo.Margin = New-Object System.Windows.Thickness(0,0,8,0)
    [System.Windows.Controls.Grid]::SetColumn($colCombo, 1)

    $aliasTxt = New-Object System.Windows.Controls.TextBox
    $aliasTxt.Margin = New-Object System.Windows.Thickness(0,0,8,0)
    $aliasTxt.ToolTip = 'Optional alias, e.g. Logons'
    [System.Windows.Controls.Grid]::SetColumn($aliasTxt, 2)

    $rmBtn = New-Object System.Windows.Controls.Button
    $rmBtn.Content = 'X'
    $rmBtn.Width = 30
    $rmBtn.Add_Click({ $KqlAggStack.Children.Remove($row); & $buildKqlQuery }.GetNewClosure())
    [System.Windows.Controls.Grid]::SetColumn($rmBtn, 3)

    [void]$row.Children.Add($funcCombo)
    [void]$row.Children.Add($colCombo)
    [void]$row.Children.Add($aliasTxt)
    [void]$row.Children.Add($rmBtn)
    $row.Tag = @{ FuncControl = $funcCombo; ColControl = $colCombo; AliasControl = $aliasTxt }

    $funcCombo.Add_SelectionChanged({ & $buildKqlQuery }.GetNewClosure())
    $funcCombo.Add_LostFocus({ & $buildKqlQuery }.GetNewClosure())
    $colCombo.Add_LostFocus({ & $buildKqlQuery }.GetNewClosure())
    $aliasTxt.Add_LostFocus({ & $buildKqlQuery }.GetNewClosure())

    [void]$KqlAggStack.Children.Add($row)
    & $buildKqlQuery
}

# --- Wire all KQL Builder events ---
$KqlTableCombo.Add_SelectionChanged({ & $updateKqlColumns; & $buildKqlQuery })
$KqlTableCombo.Add_LostFocus({       & $updateKqlColumns; & $buildKqlQuery })
$KqlTimeCombo.Add_SelectionChanged({
    if ($KqlTimeCombo.SelectedItem -eq 'Custom...') {
        $KqlCustomTimeTxt.Visibility = 'Visible'
    } else {
        $KqlCustomTimeTxt.Visibility = 'Collapsed'
    }
    & $buildKqlQuery
})
$KqlCustomTimeTxt.Add_LostFocus({ & $buildKqlQuery })

$KqlAddFilterBtn.Add_Click({   & $addKqlFilterRow })
$KqlClearFiltersBtn.Add_Click({ $KqlFiltersStack.Children.Clear(); & $buildKqlQuery })

$KqlAddExtendBtn.Add_Click({   & $addKqlExtendRow })
$KqlClearExtendBtn.Add_Click({ $KqlExtendStack.Children.Clear(); & $buildKqlQuery })

$KqlAddAggBtn.Add_Click({   & $addKqlAggRow })
$KqlClearAggBtn.Add_Click({ $KqlAggStack.Children.Clear(); & $buildKqlQuery })

$KqlBinTimeCombo.Add_SelectionChanged({ & $buildKqlQuery })
$KqlGroupByTxt.Add_LostFocus({           & $buildKqlQuery })

$KqlProjectMode_Project.Add_Click({     & $buildKqlQuery })
$KqlProjectMode_ProjectAway.Add_Click({ & $buildKqlQuery })
$KqlProjectAllBtn.Add_Click({
    foreach ($i in $KqlProjectList.Items) {
        if ($i -is [System.Windows.Controls.CheckBox]) { $i.IsChecked = $true }
    }
    & $buildKqlQuery
})
$KqlProjectNoneBtn.Add_Click({
    foreach ($i in $KqlProjectList.Items) {
        if ($i -is [System.Windows.Controls.CheckBox]) { $i.IsChecked = $false }
    }
    & $buildKqlQuery
})

$KqlOrderColCombo.Add_LostFocus({       & $buildKqlQuery })
$KqlOrderDirCombo.Add_SelectionChanged({ & $buildKqlQuery })
$KqlTakeTxt.Add_LostFocus({              & $buildKqlQuery })
$KqlTakeMode.Add_SelectionChanged({      & $buildKqlQuery })

$KqlBuildBtn.Add_Click({ & $buildKqlQuery })
$KqlCopyBtn.Add_Click({
    if ($KqlOutputTxt.Text) {
        [System.Windows.Clipboard]::SetText($KqlOutputTxt.Text)
        $KqlOutputStatusLbl.Text = "Copied to clipboard at " + (Get-Date).ToString('HH:mm:ss')
    }
})
$KqlResetBtn.Add_Click({
    $KqlFiltersStack.Children.Clear()
    $KqlExtendStack.Children.Clear()
    $KqlAggStack.Children.Clear()
    foreach ($i in $KqlProjectList.Items) {
        if ($i -is [System.Windows.Controls.CheckBox]) { $i.IsChecked = $false }
    }
    $KqlGroupByTxt.Text       = ''
    $KqlTakeTxt.Text          = '100'
    $KqlOrderColCombo.Text    = ''
    $KqlBinTimeCombo.SelectedIndex = 0
    $KqlProjectMode_Project.IsChecked = $true
    & $buildKqlQuery
})

$KqlTemplatesList.Add_SelectionChanged({
    if ($KqlTemplatesList.SelectedItem) {
        $KqlTemplatePreviewTxt.Text = $KqlTemplatesList.SelectedItem.Tag
    }
})
$KqlApplyTemplateBtn.Add_Click({
    if ($KqlTemplatesList.SelectedItem) {
        $KqlOutputTxt.Text       = $KqlTemplatesList.SelectedItem.Tag
        $KqlOutputStatusLbl.Text = "Loaded template: " + $KqlTemplatesList.SelectedItem.Content
    }
})

# Initial state
$KqlTableCombo.SelectedIndex = 0
& $updateKqlColumns
& $buildKqlQuery

# ============================================================
# Feed-update launcher (spawns child PowerShell, auto-closes)
# ============================================================
$psExe       = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
$cveKevPath  = Join-Path $script:ModulesDir 'Update-CveKevFeed.ps1'
$mitrePath   = Join-Path $script:ModulesDir 'MitreAttackExplorer.ps1'
$epssPath    = Join-Path $script:ModulesDir 'Update-EpssFeed.ps1'

$startUpdate = {
    param([string]$ScriptPath, [string]$ExtraArgs, [string]$Caption)
    if (-not (Test-Path $ScriptPath)) {
        $JobStatusLbl.Text       = "Script not found: $ScriptPath"
        $JobStatusLbl.Foreground = $DangerBrush
        return
    }
    try {
        # Mirror everything the child script writes to a transcript so the
        # user can read errors even after the window closes. One file per
        # launch, timestamped, kept in %TEMP%.
        $logPath = Join-Path $env:TEMP ("SocDash_{0}_{1}.log" -f ($Caption -replace '[^A-Za-z0-9]','_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $cmd = "Set-Location -LiteralPath '$script:ModulesDir'; " +
               "Start-Transcript -Path '$logPath' -Force | Out-Null; " +
               "Write-Host '====== $Caption ======' -ForegroundColor Cyan; " +
               "Write-Host ('Transcript: ' + '$logPath') -ForegroundColor DarkGray; " +
               "Write-Host ''; " +
               "`$__failed = `$false; " +
               "try { & '$ScriptPath' $ExtraArgs } catch { `$__failed = `$true; Write-Host ''; Write-Host 'ERROR:' -ForegroundColor Red; Write-Host `$_.Exception.Message -ForegroundColor Red; if (`$_.ScriptStackTrace) { Write-Host `$_.ScriptStackTrace -ForegroundColor DarkGray } }; " +
               "Stop-Transcript | Out-Null; " +
               "Write-Host ''; " +
               "if (`$__failed) { " +
                   "Write-Host '====== Script reported an error - window will stay open. ======' -ForegroundColor Yellow; " +
                   "Write-Host ('Full transcript at: ' + '$logPath') -ForegroundColor Yellow; " +
                   "Write-Host 'Press Enter to close.' -ForegroundColor DarkGray; " +
                   "[void][Console]::ReadLine()" +
               "} else { " +
                   "Write-Host 'Done. Closing window...' -ForegroundColor Green; " +
                   "for (`$__i=5; `$__i -ge 1; `$__i--) { Write-Host (`"  closing in `${__i}s (Ctrl+C to keep open)`") -ForegroundColor DarkGray; Start-Sleep -Seconds 1 }" +
               "}"
        $argsList = @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$cmd)
        $proc = Start-Process -FilePath $psExe -ArgumentList $argsList -PassThru -WorkingDirectory $script:ModulesDir
        $JobStatusLbl.Text       = "Started: $Caption (pid $($proc.Id)) - log: $logPath"
        $JobStatusLbl.Foreground = $AccentAltBrush
    } catch {
        $JobStatusLbl.Text       = "Failed to launch: $_"
        $JobStatusLbl.Foreground = $DangerBrush
    }
}

# ============================================================
# Tab-aware Refresh View
# ============================================================
$refreshActiveTab = {
    $sel = $MainTabs.SelectedItem
    if (-not $sel) { return }
    if ($sel -eq $MitreTab) {
        $sub = $MitreSubTabs.SelectedItem
        if ($sub -and $sub.Tag -is [hashtable] -and $sub.Tag.Loader) {
            try { & $sub.Tag.Loader } catch {}
        }
        return
    }
    if ($sel.Tag -is [hashtable] -and $sel.Tag.Loader) {
        try { & $sel.Tag.Loader } catch {}
    }
}

# ============================================================
# Wire up button click handlers
# ============================================================
$RefreshBtn.Add_Click({   & $refreshActiveTab })
$BtnUpdateKev.Add_Click({   & $startUpdate $cveKevPath '-SkipCves'      'CISA KEV refresh' })
$BtnUpdateCve.Add_Click({   & $startUpdate $cveKevPath '-SkipKevs'      'NVD CVE refresh (last 30d)' })
$BtnUpdateEpss.Add_Click({  & $startUpdate $epssPath   '-Force'         'EPSS scores refresh (FIRST.org daily)' })
$BtnUpdateMitre.Add_Click({ & $startUpdate $mitrePath  '-Update -NoGui' 'MITRE ATT&CK framework refresh' })

# ============================================================
# Tab-change auto-refresh
# ============================================================
$MainTabs.Add_SelectionChanged({
    param($s, $e)
    if ($e.OriginalSource -ne $MainTabs) { return }
    & $refreshActiveTab
})

$MitreSubTabs.Add_SelectionChanged({
    param($s, $e)
    if ($e.OriginalSource -ne $MitreSubTabs) { return }
    $sub = $MitreSubTabs.SelectedItem
    if ($sub -and $sub.Tag -is [hashtable] -and $sub.Tag.Loader) {
        try { & $sub.Tag.Loader } catch {}
    }
})

# ============================================================
# Initial dashboard paint after first layout pass
# ============================================================
if (-not $NoLoad) {
    $window.Add_ContentRendered({ & $refreshDash })
}

# ============================================================
# Show modal
# ============================================================
[void]$window.ShowDialog()
