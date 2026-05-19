using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Windows.Forms;
using AnyWhere.Telemetry;

namespace AnyWhere
{
    internal sealed class InvestigationForm : Form
    {
        private readonly EvidenceDatabase _database;
        private readonly Timer _refreshTimer = new Timer();
        private readonly DataGridView _casesGrid = new DataGridView();
        private readonly DataGridView _timelineGrid = new DataGridView();
        private readonly DataGridView _processGrid = new DataGridView();
        private readonly DataGridView _memoryGrid = new DataGridView();
        private readonly DataGridView _driverGrid = new DataGridView();
        private readonly DataGridView _hardwareGrid = new DataGridView();
        private readonly DataGridView _commGrid = new DataGridView();
        private readonly DataGridView _artifactGrid = new DataGridView();
        private readonly DataGridView _notesGrid = new DataGridView();
        private readonly TextBox _searchBox = new TextBox();
        private readonly TextBox _tagBox = new TextBox();
        private readonly TextBox _noteBox = new TextBox();
        private readonly ComboBox _statusBox = new ComboBox();
        private readonly Label _caseHeader = new Label();
        private string _selectedCaseId;
        private bool _loading;

        public InvestigationForm(EvidenceDatabase database)
        {
            _database = database;
            _database.Initialize();
            BuildInterface();
            LoadCases();

            _refreshTimer.Interval = 5000;
            _refreshTimer.Tick += delegate { RefreshCurrentView(false); };
            _refreshTimer.Start();
        }

        private void BuildInterface()
        {
            Text = "Aegis AnyWhere Investigation";
            Width = 1380;
            Height = 860;
            MinimumSize = new Size(1100, 680);
            Font = new Font("Segoe UI", 9F);
            BackColor = Color.FromArgb(245, 247, 250);

            SplitContainer shell = new SplitContainer
            {
                Dock = DockStyle.Fill,
                SplitterDistance = 370,
                BackColor = BackColor
            };
            Controls.Add(shell);

            Panel left = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12), BackColor = Color.FromArgb(250, 251, 253) };
            shell.Panel1.Controls.Add(left);

            Label title = new Label
            {
                Text = "Cases",
                Dock = DockStyle.Top,
                Height = 30,
                Font = new Font("Segoe UI Semibold", 12F),
                ForeColor = Color.FromArgb(31, 41, 55)
            };
            left.Controls.Add(title);

            _searchBox.Dock = DockStyle.Top;
            _searchBox.Height = 28;
            _searchBox.Margin = new Padding(0, 0, 0, 8);
            _searchBox.TextChanged += delegate { LoadCases(); };
            left.Controls.Add(_searchBox);

            ConfigureGrid(_casesGrid);
            _casesGrid.Dock = DockStyle.Fill;
            _casesGrid.SelectionChanged += OnCaseSelectionChanged;
            left.Controls.Add(_casesGrid);
            _casesGrid.BringToFront();

            Panel right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12), BackColor = BackColor };
            shell.Panel2.Controls.Add(right);

            Panel header = new Panel { Dock = DockStyle.Top, Height = 106, Padding = new Padding(0, 0, 0, 10), BackColor = BackColor };
            right.Controls.Add(header);

            _caseHeader.Text = "Live Investigation";
            _caseHeader.Dock = DockStyle.Top;
            _caseHeader.Height = 32;
            _caseHeader.Font = new Font("Segoe UI Semibold", 13F);
            _caseHeader.ForeColor = Color.FromArgb(17, 24, 39);
            header.Controls.Add(_caseHeader);

            FlowLayoutPanel actions = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 64,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = true
            };
            header.Controls.Add(actions);

            _statusBox.DropDownStyle = ComboBoxStyle.DropDownList;
            _statusBox.Width = 150;
            _statusBox.Items.AddRange(new object[] { "open", "investigating", "confirmed", "false_positive", "trusted", "closed" });
            _statusBox.SelectedIndex = 0;
            actions.Controls.Add(_statusBox);

            Button statusButton = new Button { Text = "Set Status", Width = 100, Height = 28 };
            statusButton.Click += delegate { ApplyStatus(); };
            actions.Controls.Add(statusButton);

            _tagBox.Width = 180;
            actions.Controls.Add(_tagBox);

            Button tagButton = new Button { Text = "Add Tag", Width = 88, Height = 28 };
            tagButton.Click += delegate { AddTag(); };
            actions.Controls.Add(tagButton);

            _noteBox.Width = 320;
            actions.Controls.Add(_noteBox);

            Button noteButton = new Button { Text = "Add Note", Width = 92, Height = 28 };
            noteButton.Click += delegate { AddNote(); };
            actions.Controls.Add(noteButton);

            Button refreshButton = new Button { Text = "Refresh", Width = 82, Height = 28 };
            refreshButton.Click += delegate { RefreshCurrentView(true); };
            actions.Controls.Add(refreshButton);

            TabControl tabs = new TabControl { Dock = DockStyle.Fill };
            right.Controls.Add(tabs);
            tabs.BringToFront();

            AddTab(tabs, "Timeline", _timelineGrid);
            AddTab(tabs, "Processes", _processGrid);
            AddTab(tabs, "Memory", _memoryGrid);
            AddTab(tabs, "Drivers", _driverGrid);
            AddTab(tabs, "Hardware", _hardwareGrid);
            AddTab(tabs, "Communication", _commGrid);
            AddTab(tabs, "Evidence", _artifactGrid);
            AddTab(tabs, "Notes", _notesGrid);
        }

        private static void AddTab(TabControl tabs, string title, DataGridView grid)
        {
            TabPage page = new TabPage(title) { Padding = new Padding(8), BackColor = Color.White };
            ConfigureGrid(grid);
            grid.Dock = DockStyle.Fill;
            page.Controls.Add(grid);
            tabs.TabPages.Add(page);
        }

        private static void ConfigureGrid(DataGridView grid)
        {
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.AllowUserToResizeRows = false;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            grid.BackgroundColor = Color.White;
            grid.BorderStyle = BorderStyle.None;
            grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(243, 244, 246);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(55, 65, 81);
            grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9F);
            grid.DefaultCellStyle.BackColor = Color.White;
            grid.DefaultCellStyle.ForeColor = Color.FromArgb(31, 41, 55);
            grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(219, 234, 254);
            grid.DefaultCellStyle.SelectionForeColor = Color.FromArgb(17, 24, 39);
            grid.EnableHeadersVisualStyles = false;
            grid.MultiSelect = false;
            grid.ReadOnly = true;
            grid.RowHeadersVisible = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        }

        private void LoadCases()
        {
            if (_loading)
            {
                return;
            }

            _loading = true;
            try
            {
                string search = "%" + (_searchBox.Text ?? string.Empty).Trim() + "%";
                DataTable table = _database.QueryTable(
                    "SELECT case_id, status, severity, printf('%.2f', confidence) AS confidence, last_seen_utc, profile, tags, summary " +
                    "FROM cases WHERE $search='%%' OR case_id LIKE $search OR summary LIKE $search OR tags LIKE $search OR profile LIKE $search " +
                    "ORDER BY last_seen_utc DESC LIMIT 500;",
                    new Dictionary<string, object> { { "$search", search } });
                _casesGrid.DataSource = table;
            }
            finally
            {
                _loading = false;
            }
        }

        private void OnCaseSelectionChanged(object sender, EventArgs eventArgs)
        {
            if (_loading || _casesGrid.CurrentRow == null)
            {
                return;
            }

            object value = _casesGrid.CurrentRow.Cells["case_id"].Value;
            _selectedCaseId = value == null ? null : Convert.ToString(value);
            _caseHeader.Text = string.IsNullOrWhiteSpace(_selectedCaseId) ? "Live Investigation" : _selectedCaseId;
            LoadCaseDetails();
        }

        private void RefreshCurrentView(bool reloadCases)
        {
            if (reloadCases)
            {
                LoadCases();
            }

            LoadCaseDetails();
        }

        private void LoadCaseDetails()
        {
            string caseFilter = _selectedCaseId ?? string.Empty;
            Dictionary<string, object> parameters = new Dictionary<string, object> { { "$caseId", caseFilter } };

            _timelineGrid.DataSource = _database.QueryTable(
                TimelineSql("1=1"),
                parameters);

            _processGrid.DataSource = _database.QueryTable(
                TimelineSql("process_id IS NOT NULL OR process_name IS NOT NULL OR json LIKE '%source_process%' OR json LIKE '%target_process%'"),
                parameters);

            _memoryGrid.DataSource = _database.QueryTable(
                TimelineSql("category LIKE '%Memory%' OR action LIKE '%Memory%' OR action LIKE '%Rwx%' OR action LIKE '%Mapped%' OR description LIKE '%memory%'"),
                parameters);

            _driverGrid.DataSource = _database.QueryTable(
                TimelineSql("category LIKE '%HiddenKernel%' OR category LIKE '%TransientDriver%' OR action LIKE '%Driver%' OR description LIKE '%.sys%' OR path LIKE '%.sys%'"),
                parameters);

            _hardwareGrid.DataSource = _database.QueryTable(
                TimelineSql("category LIKE '%HardwareIdentity%' OR description LIKE '%HWID%' OR description LIKE '%SMBIOS%' OR description LIKE '%MAC%' OR description LIKE '%serial%'"),
                parameters);

            _commGrid.DataSource = _database.QueryTable(
                TimelineSql("category LIKE '%KernelComm%' OR action LIKE '%Communication%' OR action LIKE '%LocalController%' OR json LIKE '%namedpipe%' OR json LIKE '%ALPC%' OR json LIKE '%websocket%'"),
                parameters);

            _artifactGrid.DataSource = _database.QueryTable(
                "SELECT a.artifact_type, a.value, a.seen_count, a.first_seen_utc, a.last_seen_utc, ae.case_id " +
                "FROM artifacts a LEFT JOIN artifact_events ae ON ae.artifact_id=a.artifact_id " +
                "WHERE $caseId='' OR ae.case_id=$caseId ORDER BY a.last_seen_utc DESC LIMIT 1000;",
                parameters);

            _notesGrid.DataSource = _database.QueryTable(
                "SELECT timestamp_utc, analyst, note FROM case_notes WHERE case_id=$caseId ORDER BY timestamp_utc DESC;",
                parameters);
        }

        private static string TimelineSql(string whereClause)
        {
            return "SELECT timestamp_utc, severity, category, action, process_name, process_id, path, description " +
                   "FROM events WHERE (" + whereClause + ") AND ($caseId='' OR case_id=$caseId OR event_id IN (SELECT event_id FROM case_events WHERE case_id=$caseId)) " +
                   "ORDER BY timestamp_utc DESC LIMIT 1000;";
        }

        private void ApplyStatus()
        {
            if (string.IsNullOrWhiteSpace(_selectedCaseId))
            {
                return;
            }

            _database.UpdateCaseStatus(_selectedCaseId, Convert.ToString(_statusBox.SelectedItem), "updated from investigation UI");
            LoadCases();
            LoadCaseDetails();
        }

        private void AddTag()
        {
            if (string.IsNullOrWhiteSpace(_selectedCaseId) || string.IsNullOrWhiteSpace(_tagBox.Text))
            {
                return;
            }

            _database.AddCaseTag(_selectedCaseId, _tagBox.Text.Trim());
            _tagBox.Clear();
            LoadCases();
            LoadCaseDetails();
        }

        private void AddNote()
        {
            if (string.IsNullOrWhiteSpace(_selectedCaseId) || string.IsNullOrWhiteSpace(_noteBox.Text))
            {
                return;
            }

            _database.AddCaseNote(_selectedCaseId, _noteBox.Text.Trim(), Environment.UserName);
            _noteBox.Clear();
            LoadCaseDetails();
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            _refreshTimer.Stop();
            _refreshTimer.Dispose();
            base.OnFormClosed(e);
        }
    }
}
