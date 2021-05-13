Execute this commands in the directory with the ''Dockerfile'':

# Build the image:

	docker build -t antidosvalve_demo .

# Run the demo server:

After you build the JAR file start a tomcat instance:

	docker run --mount type=bind,source="%cd%"/../target/anti-dos-valve-1.3.0.jar,target=/usr/local/tomcat/lib/anti-dos-valve.jar,readonly  --mount type=bind,source="%cd%"/server.xml,target=/usr/local/tomcat/conf/server.xml,readonly  --mount type=bind,source="%cd%"/advdemo/,target=/usr/local/tomcat/webapps/advdemo/,readonly --name AntiDoSValveDemo -p 8013:8080 -it antidosvalve_demo

For linux boxes: replace "%cd%" with "$(pwd)"

You can now access the server under [Port 8013](http://localhost:8013). You will get a 404 message because all tomcat demo webapps are removed.

Try the adress [/valvetest](http://localhost:8013/valvetest) more then 5 times and you will see the valve working in blocking mode in the browser and in the server log. 

Then try the adress [/advdemo/advdemo.jsp](http://localhost:8013/advdemo/advdemo.jsp) more then 5 times and you will see the valve working in marking mode. 

# Remove the container:

	docker rm AntiDoSValveDemo

