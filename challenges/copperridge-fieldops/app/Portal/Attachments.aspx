<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    // ------------------------------------------------------------------
    // Component failure photograph upload.
    //
    // Mechanics attach photographs of failed components to a downtime
    // entry so the reliability group can review them without walking the
    // pit. Images and scanned PDFs only.
    // ------------------------------------------------------------------

    static readonly string[] BlockedExtensions =
        { ".aspx", ".asp", ".ashx", ".asmx", ".aspq", ".cshtml", ".config", ".cs", ".vb" };

    static readonly string[] AllowedContentTypes =
        { "image/jpeg", "image/png", "image/gif", "application/pdf" };

    string UploadDir { get { return Server.MapPath("~/Uploads"); } }

    protected void Page_Load(object sender, EventArgs e)
    {
        if (Session["auth"] == null)
        {
            Response.Redirect("~/Login.aspx");
            return;
        }
        if (!IsPostBack) { BindFileList(); }
    }

    protected void DoUpload(object sender, EventArgs e)
    {
        if (fileUpload.PostedFile == null || fileUpload.PostedFile.ContentLength == 0)
        {
            ShowError("Select a photograph or scanned document to attach.");
            return;
        }

        var posted = fileUpload.PostedFile;

        // --- Gate 1: declared content type must be an image or PDF ---
        bool typeOk = false;
        foreach (string ct in AllowedContentTypes)
        {
            if (string.Equals(posted.ContentType, ct, StringComparison.OrdinalIgnoreCase))
            {
                typeOk = true;
                break;
            }
        }
        if (!typeOk)
        {
            ShowError("Attachments must be an image (JPEG, PNG, GIF) or a scanned PDF.");
            return;
        }

        // --- Gate 2: extension blacklist ---
        string fileName = Path.GetFileName(posted.FileName);
        foreach (string bad in BlockedExtensions)
        {
            // NOTE: IIS normalises the filename before it reaches the handler,
            // so a plain ordinal compare is sufficient here. -- t.brandt, CR-1402
            if (fileName.EndsWith(bad, StringComparison.Ordinal))
            {
                ShowError("That file type is not permitted as an attachment.");
                return;
            }
        }

        if (!Directory.Exists(UploadDir)) { Directory.CreateDirectory(UploadDir); }

        string target = Path.Combine(UploadDir, fileName);
        posted.SaveAs(target);

        lblStatus.CssClass = "msg-ok";
        lblStatus.Text = "Attached " + Server.HtmlEncode(fileName) + " ("
                       + posted.ContentLength + " bytes).";
        lblStatus.Visible = true;
        BindFileList();
    }

    void ShowError(string msg)
    {
        lblStatus.CssClass = "msg-err";
        lblStatus.Text = msg;
        lblStatus.Visible = true;
    }

    void BindFileList()
    {
        if (!Directory.Exists(UploadDir)) { return; }
        var rows = new System.Collections.Generic.List<object>();
        foreach (var f in new DirectoryInfo(UploadDir).GetFiles())
        {
            rows.Add(new { Name = f.Name, Size = f.Length, Modified = f.LastWriteTime });
        }
        rptFiles.DataSource = rows;
        rptFiles.DataBind();
    }
</script>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attachments :: FieldOps</title>
<link rel="stylesheet" href="/assets/fieldops.css" />
</head><body>

<div class="topbar">
  <div class="inner">
    <div>
      <span class="brand">Copper Ridge</span>
      <span class="brandsub">Mining &amp; Aggregate</span>
    </div>
    <div class="topnav">
      <a href="Downtime.aspx">Downtime Log</a>
      <a href="Attachments.aspx">Attachments</a>
      <a href="/Login.aspx">Sign Out</a>
    </div>
  </div>
</div>

<div class="strip">
  <div class="inner">
    <span><b>FIELDOPS</b> Equipment Maintenance &amp; Dispatch</span>
    <span>Component Failure Records</span>
  </div>
</div>

<div class="wrap">
  <form runat="server">

  <div class="panel">
    <h2>Attach Component Failure Photograph</h2>
    <div class="body">
      <p class="muted">
        Accepted formats: JPEG, PNG, GIF, scanned PDF. Maximum 4 MB per attachment.
        Include the unit number in the filename &mdash;
        <span class="mono">HT-214-frontidler.jpg</span>.
      </p>
      <asp:FileUpload ID="fileUpload" runat="server" />
      <asp:Button ID="btnUpload" runat="server" Text="Upload Attachment" CssClass="btn" OnClick="DoUpload" />
      <asp:Label ID="lblStatus" runat="server" Visible="false" />
    </div>
  </div>

  <div class="panel">
    <h2>Attachments On File</h2>
    <div class="body">
      <table class="grid">
        <tr><th>File</th><th>Size</th><th>Uploaded</th></tr>
        <asp:Repeater ID="rptFiles" runat="server">
          <ItemTemplate>
            <tr>
              <td class="mono"><a href='<%# "../Uploads/" + Eval("Name") %>'><%# Eval("Name") %></a></td>
              <td class="mono"><%# Eval("Size") %> B</td>
              <td class="mono"><%# Eval("Modified", "{0:yyyy-MM-dd HH:mm}") %></td>
            </tr>
          </ItemTemplate>
        </asp:Repeater>
      </table>
    </div>
  </div>

  </form>
</div>

<div class="foot">
  Copper Ridge Mining &amp; Aggregate &mdash; FieldOps <span class="mono">v3.1.4</span><br>
  TUC-WEB01 &middot; Pima County AZ
</div>

</body></html>
