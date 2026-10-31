  <%@page contentType="text/html; charset=UTF-8" session="false" %>

    <html>

    <head>
      <title>AntiDoSValve: Marking &amp; Auth Tracking Demo</title>
    </head>

    <body>
      <h1>AntiDoSValve: Marking &amp; Auth Tracking Demo</h1>

      <div>Reload the page until the marking value changes: </div>

      <blockquote>
        <strong>\${requestScope["org.henbru.antidos.AntiDoS"]}=</strong>
        <%= request.getAttribute("org.henbru.antidos.AntiDoS") %>
      </blockquote>

      <div>Authenticated Session Status (tracked via <code>AUTH_COOKIE</code> from <code>/advdemo/trust</code>):</div>

      <blockquote>
        <strong>\${requestScope["org.henbru.antidos.AUTHENTICATED"]}=</strong>
        <span id="authStatus">
          <%= request.getAttribute("org.henbru.antidos.AUTHENTICATED") %>
        </span>
      </blockquote>

      <p>
        <a href="<%= request.getContextPath() %>/trust">Simulate Login (/advdemo/trust)</a> |
        <a href="<%= request.getContextPath() %>/trust?logout=true">Simulate Logout (/advdemo/trust?logout=true)</a>
      </p>
    </body>

    </html>