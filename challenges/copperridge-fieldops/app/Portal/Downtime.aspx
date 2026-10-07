<%@ Page Language="C#" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Session["auth"] == null)
        {
            Response.Redirect("~/Login.aspx");
            return;
        }
        lblUser.Text = Server.HtmlEncode((Session["user"] ?? "").ToString());

        // Static export. The Facilities SQL instance was retired in the FY19
        // consolidation (CR-1204); FieldOps reads a flat nightly export until
        // the replacement is provisioned. Ticket has been open since.
        var rows = new[] {
            new { Unit = "HT-214", Type = "Haul Truck 793F",   State = "DOWN",    Hours = "18.5", Tech = "j.alvarez", Note = "Front idler seal failure, photos attached" },
            new { Unit = "SH-002", Type = "Shovel 6030",       State = "RUNNING", Hours = "0.0",  Tech = "-",         Note = "PM interval due in 40 hrs" },
            new { Unit = "CR-L2",  Type = "Crusher Line 2",    State = "HOLD",    Hours = "6.0",  Tech = "d.mercer",  Note = "Awaiting PLC gateway firmware from vendor" },
            new { Unit = "HT-207", Type = "Haul Truck 793F",   State = "RUNNING", Hours = "0.0",  Tech = "-",         Note = "Returned to service 02:40" },
            new { Unit = "WT-011", Type = "Water Truck",       State = "DOWN",    Hours = "31.0", Tech = "j.alvarez", Note = "Pump drive coupling, part on order" },
            new { Unit = "SVC-01", Type = "FieldSync Service", State = "DOWN",    Hours = "9.0",  Tech = "d.mercer",  Note = "CRFieldSync stops after the nightly export; IT to review the service account (CR-3301)" },
            new { Unit = "LD-004", Type = "Front Loader 994",  State = "RUNNING", Hours = "0.0",  Tech = "-",         Note = "" }
        };
        rptUnits.DataSource = rows;
        rptUnits.DataBind();
    }
</script>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Downtime Log :: FieldOps</title>
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
    <span>Signed in: <asp:Label ID="lblUser" runat="server" CssClass="mono" /></span>
  </div>
</div>

<div class="wrap">
  <div class="panel">
    <h2>Unplanned Downtime &mdash; Pit 4, Shift B</h2>
    <div class="body">
      <table class="grid">
        <tr>
          <th>Unit</th><th>Equipment</th><th>State</th>
          <th>Down Hrs</th><th>Assigned</th><th>Note</th>
        </tr>
        <asp:Repeater ID="rptUnits" runat="server">
          <ItemTemplate>
            <tr>
              <td class="mono"><%# Eval("Unit") %></td>
              <td><%# Eval("Type") %></td>
              <td class='<%# Eval("State").ToString() == "RUNNING" ? "ok" : (Eval("State").ToString() == "HOLD" ? "hold" : "down") %>'><%# Eval("State") %></td>
              <td class="mono"><%# Eval("Hours") %></td>
              <td class="mono"><%# Eval("Tech") %></td>
              <td><%# Eval("Note") %></td>
            </tr>
          </ItemTemplate>
        </asp:Repeater>
      </table>
      <p class="muted" style="margin-top:12px">
        All unplanned downtime must be logged before end of shift. Entries roll into the
        02:15 export for the morning production meeting.
      </p>
    </div>
  </div>
</div>

<div class="foot">
  Copper Ridge Mining &amp; Aggregate &mdash; FieldOps <span class="mono">v3.1.4</span><br>
  TUC-WEB01 &middot; Pima County AZ
</div>

</body></html>
