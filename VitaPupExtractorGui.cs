// ps vita pup extractor GUI - WinForms, .NET Framework 4.x.
// Full pup_fiction pipeline with proto->internal->external key fallback.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace VitaPupExtractor
{
    public class MainForm : Form
    {
        TextBox txtPup, txtInDir, txtOut, txtLog;
        Button btnPup, btnInDir, btnOut, btnExtract, btnBatch;
        CheckBox chkFs, chkVs0, chkSlb2;
        ProgressBar progress;
        Label lblStatus, lbl7z;

        string _sevenZip, _unarzl;

        public MainForm()
        {
            Text = "PS Vita PUP Extractor";
            ClientSize = new Size(800, 560);
            MinimumSize = new Size(640, 460);
            Font = new Font("Segoe UI", 9f);
            StartPosition = FormStartPosition.CenterScreen;
            AllowDrop = true;
            DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            DragDrop += (s, e) => { var f = (string[])e.Data.GetData(DataFormats.FileDrop); if (f != null && f.Length > 0) SetPup(f[0]); };

            _sevenZip = VitaPup.FindSevenZip();
            _unarzl = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "unarzl.exe");

            int bw = 95, bx = 686;
            var lblPup = new Label { Text = "PUP file:", Left = 12, Top = 15, Width = 90 };
            txtPup = new TextBox { Left = 105, Top = 12, Width = 568, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            btnPup = new Button { Text = "Browse...", Left = bx, Top = 10, Width = bw, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnPup.Click += (s, e) => BrowsePup();

            var lblIn = new Label { Text = "Input folder:", Left = 12, Top = 47, Width = 90 };
            txtInDir = new TextBox { Left = 105, Top = 44, Width = 568, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            btnInDir = new Button { Text = "Browse...", Left = bx, Top = 42, Width = bw, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnInDir.Click += (s, e) => BrowseFolder(txtInDir, "Folder containing the PUP files (batch)");

            var lblOut = new Label { Text = "Output folder:", Left = 12, Top = 79, Width = 90 };
            txtOut = new TextBox { Left = 105, Top = 76, Width = 568, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            btnOut = new Button { Text = "Browse...", Left = bx, Top = 74, Width = bw, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnOut.Click += (s, e) => BrowseFolder(txtOut, "Output folder");

            chkFs = new CheckBox { Text = "Extract filesystems (7-Zip)", Left = 105, Top = 108, Width = 210, Checked = _sevenZip != null, Enabled = _sevenZip != null };
            chkVs0 = new CheckBox { Text = "Include vs0 / vd0 (large)", Left = 320, Top = 108, Width = 190, Checked = true };
            chkSlb2 = new CheckBox { Text = "Decrypt SLB2 / boot", Left = 515, Top = 108, Width = 160, Checked = true };
            chkFs.CheckedChanged += (s, e) => chkVs0.Enabled = chkFs.Checked && _sevenZip != null;

            btnExtract = new Button { Text = "Extract", Left = 105, Top = 134, Width = 110, Height = 26 };
            btnExtract.Click += (s, e) => StartSingle();
            btnBatch = new Button { Text = "Batch folder", Left = 225, Top = 134, Width = 110, Height = 26 };
            btnBatch.Click += (s, e) => StartBatch();

            lbl7z = new Label { Left = 350, Top = 139, Width = 440, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                ForeColor = _sevenZip != null ? Color.Green : Color.DarkOrange,
                Text = (_sevenZip != null ? "7-Zip OK" : "7-Zip not found (os0/vs0 left raw)") + (File.Exists(_unarzl) ? "" : " | unarzl.exe missing") };

            var lblKeys = new Label { Left = 12, Top = 166, Width = 778, ForeColor = Color.Gray, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                Text = "Key fallback order: proto (External GEN2)  ->  internal (Internal GENX)  ->  external (External GEN3)" };

            txtLog = new TextBox
            {
                Left = 12, Top = 188, Width = 776, Height = 330,
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false,
                Font = new Font("Consolas", 9f), BackColor = Color.FromArgb(24, 24, 24), ForeColor = Color.Gainsboro,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };
            progress = new ProgressBar { Left = 12, Top = 526, Width = 640, Height = 20, Style = ProgressBarStyle.Blocks, Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
            lblStatus = new Label { Left = 660, Top = 528, Width = 128, Text = "Ready", Anchor = AnchorStyles.Bottom | AnchorStyles.Right };

            Controls.AddRange(new Control[] { lblPup, txtPup, btnPup, lblIn, txtInDir, btnInDir, lblOut, txtOut, btnOut,
                chkFs, chkVs0, chkSlb2, btnExtract, btnBatch, lbl7z, lblKeys, txtLog, progress, lblStatus });
        }

        void BrowsePup()
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Filter = "PS Vita update package (*.pup;*.PUP)|*.pup;*.PUP|All files (*.*)|*.*";
                if (dlg.ShowDialog(this) == DialogResult.OK) SetPup(dlg.FileName);
            }
        }
        void SetPup(string path)
        {
            txtPup.Text = path;
            if (txtOut.Text.Length == 0)
                txtOut.Text = Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path) + "_ex");
        }
        void BrowseFolder(TextBox target, string desc)
        {
            using (var dlg = new FolderBrowserDialog()) { dlg.Description = desc; if (dlg.ShowDialog(this) == DialogResult.OK) target.Text = dlg.SelectedPath; }
        }

        void Log(string s) { if (txtLog.InvokeRequired) { txtLog.BeginInvoke((Action<string>)Log, s); return; } txtLog.AppendText(s + "\r\n"); }
        void SetStatus(string s) { if (lblStatus.InvokeRequired) { lblStatus.BeginInvoke((Action<string>)SetStatus, s); return; } lblStatus.Text = s; }
        void SetBusy(bool busy)
        {
            if (InvokeRequired) { BeginInvoke((Action<bool>)SetBusy, busy); return; }
            btnExtract.Enabled = btnBatch.Enabled = btnPup.Enabled = btnInDir.Enabled = btnOut.Enabled =
                txtPup.Enabled = txtInDir.Enabled = txtOut.Enabled = chkSlb2.Enabled = !busy;
            chkFs.Enabled = !busy && _sevenZip != null;
            chkVs0.Enabled = !busy && chkFs.Checked && _sevenZip != null;
            progress.Style = busy ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks;
            UseWaitCursor = busy;
        }

        VitaPup.Options MakeOpts() { return new VitaPup.Options { ExtractFilesystems = chkFs.Checked, IncludeVs0 = chkVs0.Checked, DecryptSlb2 = chkSlb2.Checked, SevenZip = _sevenZip, UnarzlExe = _unarzl }; }

        void StartSingle()
        {
            string pup = txtPup.Text.Trim(), outDir = txtOut.Text.Trim();
            if (pup.Length == 0 || !File.Exists(pup)) { MessageBox.Show(this, "Select a valid PUP file in the 'PUP file' field."); return; }
            if (outDir.Length == 0) { outDir = Path.Combine(Path.GetDirectoryName(pup), Path.GetFileNameWithoutExtension(pup) + "_ex"); txtOut.Text = outDir; }
            var opt = MakeOpts();
            txtLog.Clear(); SetBusy(true); SetStatus("Working...");
            RunThread(() =>
            {
                try { VitaPup.ExtractPup(pup, outDir, opt, VitaKeyStores.All, Log); Done(true); }
                catch (Exception ex) { Log("\nERROR: " + ex.Message); Done(false); }
            });
        }

        void StartBatch()
        {
            string inDir = txtInDir.Text.Trim(), parent = txtOut.Text.Trim();
            if (inDir.Length == 0 || !Directory.Exists(inDir)) { MessageBox.Show(this, "Set a valid 'Input folder' (folder containing PUPs)."); return; }
            if (parent.Length == 0) { MessageBox.Show(this, "Set an 'Output folder'."); return; }
            var list = new List<string>();
            try { foreach (string f in Directory.GetFiles(inDir, "*.pup", SearchOption.AllDirectories)) list.Add(f); }
            catch (Exception ex) { MessageBox.Show(this, "Cannot read folder: " + ex.Message); return; }
            list.Sort(StringComparer.OrdinalIgnoreCase);
            if (list.Count == 0) { MessageBox.Show(this, "No .pup files found in:\n" + inDir); return; }
            var files = list.ToArray(); var opt = MakeOpts();
            txtLog.Clear(); SetBusy(true); SetStatus("Batch...");
            Log(string.Format("Batch: {0} PUP(s) from {1}\n  -> {2}", files.Length, inDir, parent));
            RunThread(() =>
            {
                int ok = 0, fail = 0;
                for (int i = 0; i < files.Length; i++)
                {
                    string f = files[i];
                    string outDir = UniqueDir(parent, Path.GetFileNameWithoutExtension(f) + "_ex");
                    Log(string.Format("\n===== [{0}/{1}] {2} =====", i + 1, files.Length, Path.GetFileName(f)));
                    SetStatus(string.Format("Batch {0}/{1}", i + 1, files.Length));
                    try { VitaPup.ExtractPup(f, outDir, opt, VitaKeyStores.All, Log); ok++; }
                    catch (Exception ex) { Log("  ERROR: " + ex.Message); fail++; }
                }
                Log(string.Format("\nBatch done. OK={0} FAIL={1}", ok, fail));
                Done(fail == 0);
            });
        }

        static string UniqueDir(string parent, string name)
        {
            string p = Path.Combine(parent, name);
            if (!Directory.Exists(p) || !Directory.EnumerateFileSystemEntries(p).GetEnumerator().MoveNext()) return p;
            for (int k = 2; ; k++) { string q = Path.Combine(parent, name + "_" + k); if (!Directory.Exists(q)) return q; }
        }

        void RunThread(ThreadStart work) { var t = new Thread(work); t.IsBackground = true; t.Start(); }
        void Done(bool ok) { SetBusy(false); SetStatus(ok ? "Done" : "Finished with errors"); }

        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var f = new MainForm();
            if (args.Length >= 1) f.Shown += (s, e) => f.SetPup(args[0]);
            Application.Run(f);
        }
    }
}
