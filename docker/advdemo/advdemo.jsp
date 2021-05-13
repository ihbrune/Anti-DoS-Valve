<%@page contentType="text/html; charset=UTF-8" %>

<html>
  <head>
    <title>AntiDoSValve: Marking mode demo</title>
  </head>
  <body>
    <h1>AntiDoSValve: Marking mode demo</h1>

    <div>Reload the page until this value changes: </div>

    <blockquote>
            <strong>\${requestScope["org.henbru.antidos.AntiDoS"]}=</strong>
            ${requestScope["org.henbru.antidos.AntiDoS"]}
    </blockquote>
  </body>
</html>
