// Authenticated windowed host. UI code is compiled into the signed PE; no
// downloaded script, execution-policy switch, runtime or credential in argv.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Security;
using System.Text;
using System.Threading;
using System.Windows.Forms;

internal static class P6Launcher {
    private const string Publisher = "@P6_PUBLISHER@";
    private const string CompiledSetup = "@P6_COMPILED_SETUP@";
    [STAThread]
    private static int Main(string[] args) {
        Runspace space = null;
        string stage = "entry";
        try {
            if (args.Length != 0 || !Environment.Is64BitProcess) throw new InvalidOperationException();
            string root = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var host = new P6Host();
            space = RunspaceFactory.CreateRunspace(host);
            space.ApartmentState = ApartmentState.STA;
            space.ThreadOptions = PSThreadOptions.UseCurrentThread;
            space.Open();
            Runspace.DefaultRunspace = space;
            space.SessionStateProxy.SetVariable("P6CompiledPackageRoot", root);
            // Hold the three signed entry objects against write/delete until
            // the authenticated GUI returns. Protected copying repeats gates.
            string gate = "$ErrorActionPreference='Stop';$PSModuleAutoloadingPreference='None';$h=@();" +
                "foreach($m in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {" +
                "Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$m,($m+'.psd1'))) -ErrorAction Stop};" +
                "$p=$P6CompiledPackageRoot;$n=[IO.Path]::GetFullPath($p);" +
                "if($n.StartsWith('\\\\') -or $n.Substring(2).Contains(':')){throw 'path'};" +
                "while($n){if(([IO.File]::GetAttributes($n) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'path'};" +
                "$q=[IO.Path]::GetDirectoryName($n);if($q -eq $n){break};$n=$q};" +
                "foreach($f in @('P6Setup.exe','Setup.ps1','payload.cat')) {" +
                "$x=Join-Path $p $f;if(([IO.File]::GetAttributes($x) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'path'};" +
                "$h+=New-Object IO.FileStream($x,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);if($h[-1].Length -gt 4194304){throw 'capacity'};" +
                "$s=Get-AuthenticodeSignature -LiteralPath $x;" +
                "if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne '" + Publisher + "'){throw 'publisher'}}";
            stage = "signature";
            using (var shell = PowerShell.Create()) {
                shell.Runspace = space;
                shell.AddScript(gate, false).Invoke();
                if (shell.HadErrors) throw new InvalidOperationException();
            }
            // Authenticode covers these build-embedded bytes. No script code is
            // loaded from Setup.ps1 and no execution-policy setting is changed.
            stage = "window";
            string code = Encoding.UTF8.GetString(Convert.FromBase64String(CompiledSetup));
            using (var shell = PowerShell.Create()) {
                shell.Runspace = space;
                shell.AddScript(code, false).AddParameter("Operation", "gui").Invoke();
                if (shell.HadErrors) {
                    stage = "ui_pipeline";
                    if (shell.Streams.Error.Count > 0) stage += "_" + shell.Streams.Error[0].CategoryInfo.Category.ToString();
                    throw new InvalidOperationException();
                }
                if (host.ExitCode != 0) { stage = "ui_exit"; throw new InvalidOperationException(); }
            }
            return 0;
        } catch {
            MessageBox.Show("无法打开 P6 管理。请确认安装包来自可信发布者、签名有效且文件完整。", "P6 管理 · E_" + stage, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 2;
        } finally {
            if (space != null) {
                try {
                    var handles = space.SessionStateProxy.GetVariable("h") as IEnumerable;
                    if (handles != null) foreach (var value in handles) {
                        var wrapped = value as PSObject;
                        var disposable = (wrapped == null ? value : wrapped.BaseObject) as IDisposable;
                        if (disposable != null) disposable.Dispose();
                    }
                } catch { }
                space.Dispose();
            }
        }
    }
}

// The authenticated GUI owns interaction; there is no console or transcript.
internal sealed class P6Host : PSHost {
    private readonly Guid id = Guid.NewGuid();
    private readonly P6HostUI ui = new P6HostUI();
    public int ExitCode = -1;
    public override Guid InstanceId { get { return id; } }
    public override string Name { get { return "P6SignedManager"; } }
    public override Version Version { get { return new Version(1, 0); } }
    public override PSHostUserInterface UI { get { return ui; } }
    public override CultureInfo CurrentCulture { get { return CultureInfo.CurrentCulture; } }
    public override CultureInfo CurrentUICulture { get { return CultureInfo.CurrentUICulture; } }
    public override void SetShouldExit(int code) { ExitCode = code; }
    public override void EnterNestedPrompt() { throw new NotSupportedException(); }
    public override void ExitNestedPrompt() { throw new NotSupportedException(); }
    public override void NotifyBeginApplication() { }
    public override void NotifyEndApplication() { }
}
internal sealed class P6HostUI : PSHostUserInterface {
    private readonly P6RawUI raw = new P6RawUI();
    public override PSHostRawUserInterface RawUI { get { return raw; } }
    public override string ReadLine() { throw new NotSupportedException(); }
    public override SecureString ReadLineAsSecureString() { throw new NotSupportedException(); }
    public override Dictionary<string,PSObject> Prompt(string c,string m,Collection<FieldDescription> d) { throw new NotSupportedException(); }
    public override int PromptForChoice(string c,string m,Collection<ChoiceDescription> d,int i) { throw new NotSupportedException(); }
    public override PSCredential PromptForCredential(string c,string m,string u,string t) { throw new NotSupportedException(); }
    public override PSCredential PromptForCredential(string c,string m,string u,string t,PSCredentialTypes p,PSCredentialUIOptions o) { throw new NotSupportedException(); }
    public override void Write(string value) { }
    public override void Write(ConsoleColor f,ConsoleColor b,string value) { }
    public override void WriteLine(string value) { }
    public override void WriteErrorLine(string value) { }
    public override void WriteDebugLine(string value) { }
    public override void WriteProgress(long id,ProgressRecord value) { }
    public override void WriteVerboseLine(string value) { }
    public override void WriteWarningLine(string value) { }
}
internal sealed class P6RawUI : PSHostRawUserInterface {
    public override ConsoleColor BackgroundColor { get; set; }
    public override ConsoleColor ForegroundColor { get; set; }
    public override Size BufferSize { get; set; }
    public override Size WindowSize { get; set; }
    public override Coordinates CursorPosition { get; set; }
    public override Coordinates WindowPosition { get; set; }
    public override int CursorSize { get; set; }
    public override string WindowTitle { get; set; }
    public override Size MaxWindowSize { get { return new Size(120,40); } }
    public override Size MaxPhysicalWindowSize { get { return new Size(120,40); } }
    public override bool KeyAvailable { get { return false; } }
    public override KeyInfo ReadKey(ReadKeyOptions o) { throw new NotSupportedException(); }
    public override void FlushInputBuffer() { }
    public override BufferCell[,] GetBufferContents(Rectangle r) { throw new NotSupportedException(); }
    public override void ScrollBufferContents(Rectangle s,Coordinates d,Rectangle c,BufferCell f) { }
    public override void SetBufferContents(Coordinates o,BufferCell[,] c) { }
    public override void SetBufferContents(Rectangle r,BufferCell c) { }
}
