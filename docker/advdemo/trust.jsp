<%@page contentType="text/html; charset=UTF-8" session="false" %>
  <% boolean isLogout="true" .equalsIgnoreCase(request.getParameter("logout")); String tokenValue=null; if (isLogout) {
    response.addHeader("Set-Cookie", "AUTH_COOKIE=; Path=/; Max-Age=0; HttpOnly" ); } else {
    tokenValue="demo-sso-token-" + java.util.UUID.randomUUID(); response.addHeader("Set-Cookie", "AUTH_COOKIE=" +
    tokenValue + "; Path=/; Max-Age=900; HttpOnly" ); } %>
    <html>

    <head>
      <title>AntiDoSValve: SSO Login Callback Demo (/trust)</title>
    </head>

    <body>
      <h1>AntiDoSValve: SSO Login Callback Demo (<code>/advdemo/trust</code>)</h1>
      <% if (isLogout) { %>
        <p><strong>Status:</strong> Logged out (<code>Set-Cookie: AUTH_COOKIE=; Max-Age=0</code> emitted).</p>
        <% } else { %>
          <p><strong>Status:</strong> Login successful! Issued <code>AUTH_COOKIE</code> with <code>Max-Age=900</code>.
          </p>
          <p><strong>Token Value:</strong> <code><%= tokenValue %></code></p>
          <% } %>
            <p>
              <a href="<%= request.getContextPath() %>/advdemo.jsp">Go to /advdemo/advdemo.jsp to verify authenticated
                status</a> |
              <a href="<%= request.getContextPath() %>/trust">Issue new login cookie</a> |
              <a href="<%= request.getContextPath() %>/trust?logout=true">Simulate Logout (Max-Age=0)</a>
            </p>
    </body>

    </html>