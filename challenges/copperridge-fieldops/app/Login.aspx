<%@ Page Language="C#" %>
<%@ Import Namespace="System.Configuration" %>
<script runat="server">
    // FieldOps sign-in.
    //
    // Credentials live in web.config appSettings. The membership provider was
    // never migrated off the old SQL box during the FY19 consolidation
    // (CR-1204) and Dispatch only ever needed the one supervisor account.
    protected void DoLogin(object sender, EventArgs e)
    {
        string user = (txtUser.Text ?? "").Trim();
        string pass = txtPass.Text ?? "";

        string expectedUser = ConfigurationManager.AppSettings["FieldOpsUser"];
        string expectedPass = ConfigurationManager.AppSettings["FieldOpsPassword"];

        if (string.Equals(user, expectedUser, StringComparison.OrdinalIgnoreCase) && pass == expectedPass)
        {
            Session["auth"] = true;
            Session["user"] = user;
            Response.Redirect("~/Portal/Downtime.aspx");
            return;
        }

        lblError.Text = "Sign in failed. Check your employee ID and password.";
        lblError.Visible = true;
    }
</script>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In :: FieldOps</title>
<link rel="stylesheet" href="/assets/fieldops.css" />
<style>
.loginwrap { max-width: 400px; margin: 40px auto 0; padding: 0 18px; }
</style>
</head><body>

<div class="topbar">
  <div class="inner">
    <div>
      <span class="brand">Copper Ridge</span>
      <span class="brandsub">Mining &amp; Aggregate</span>
    </div>
  </div>
</div>

<div class="strip">
  <div class="inner">
    <span><b>FIELDOPS</b> Equipment Maintenance &amp; Dispatch</span>
    <span>Authorised Personnel Only</span>
  </div>
</div>

<div class="loginwrap">
  <div class="panel">
    <h2>Employee Sign In</h2>
    <div class="body">
      <form runat="server">
        <label for="txtUser">Employee ID</label>
        <asp:TextBox ID="txtUser" runat="server" />
        <label for="txtPass">Password</label>
        <asp:TextBox ID="txtPass" runat="server" TextMode="Password" />
        <asp:Button ID="btnLogin" runat="server" Text="Sign In" CssClass="btn" OnClick="DoLogin" />
        <asp:Label ID="lblError" runat="server" CssClass="msg-err" Visible="false" />
      </form>
      <p class="muted" style="margin-top:16px">
        Access to this system is restricted to authorised Copper Ridge personnel.
        Activity is logged. Report lost credentials to the IT desk on extension 2280.
      </p>
    </div>
  </div>
</div>

<div class="foot">
  Copper Ridge Mining &amp; Aggregate &mdash; FieldOps <span class="mono">v3.1.4</span><br>
  TUC-WEB01 &middot; Pima County AZ
</div>

</body></html>
