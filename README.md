
# What is the Anti-DoS Valve
This project implements a Tomcat Valve, which can enforce dynamic access rate limitations on requests from individual IP addresses. This can, to a certain extent, prevent overloads of Tomcat servers, eg by DoS attacks, or at least limit their effects.

The valve can not, of course, provide complete protection against any kind of maliciously caused overload. The goal is rather to get a simple usable DoS protection, which can be put into operation at short notice and with little effort, causing only a small overhead in the Tomcat server and can be used in particular to slow down aggressive web crawlers.

The valve can be extensively configured and additionally offers the option to block individual IP addresses or groups of addresses in general or to completely exclude IP adresses from a blockade.

An important goal in the development is the extensive coverage of the code by unittests, which is to guarantee the correct function of this code at a central point in the Tomcat server.

Also a simulation option in the form of Google Drive Sheets is provided. The status of the valve can be monitored and the configuration can be changed via JMX.

# Which version of Tomcat

The valve is build against Tomcat 8.0.* libraries. It has been tested in Tomcat 8.0.* and 8.5.*.

# Implementation of dynamic access rate limiting

The goal of the implementation was to get a flexible solution, which at the same time would only have a small degree of complexity and little overhead in the servers.

In order to check whether a specific IP address currently exceeds the allowed access rate, the model of the slots was used: The internal, so-called Anti-DoS Monitor subdivides the monitoring period into successive, non-overlapping slots of a fixed length. If this slot length is 1 minute, the slots might cover these periods:

* 12:00:00 to 12:00:59
* 12:01:00 to 12:01:59
* 12:02:00 to 12:02:59
* 12:03:00 to 12:03:59
* …

The evaluation of whether an IP address makes too many accesses refers firstly to the accesses that have taken place within the current slot. A simple counter is used for this purpose. Compared to a sliding evaluation that does not use slots this avoids the storing of the individual request events. 

For this the reason even in a DoS situation, in which thousands of requsts are made in a short time, the effort for the monitoring is not significantly higher than during normal operation. The disadvantage of the use of slots is the elimination of the past as soon as a new slot begins. Therefore the monitor contains an option to transfer counts from the previous slots.

This transfer function first calculates the mean value of the accesses counted in the previous slots. From this mean value, an adjustable portion is transferred to the new slot. Depending on the setting, a very fast or a very slow 'forgetting' of earlier load peaks in the Anti-DoS Monitor is achievable.

The Anti-DoS Monitor has a structure that looks like this:

* Current slot: 12:03:00 to 12:03:59
  * Last registered IP address: 123.0.0.1
    * Number of requests in this slot so far: 5
    * Number of retained requests from previous slots: 0
  * Previously registered IP address: 123.0.0.2
    * Number of requests in this slot so far: 1
    * Number of retained requests from previous slots: 3
   * …
* Previous slot: 12:02:00 to 12:02:59
  * ...
* …

The maximum number of allowed requests per slot per IP address is compared with the number of current requests plus the number of requests taken from previous slots. If this sum is above the limit, the access for the remaining duration of this slot is blocked. If an IP address is blocked, all its accesses are answered with the HTTP status code 403 (Forbidden).

# Experiences so far

In its first version the valve was developed for the protection of a Tomcat server farm, which processes more than 1,000,000 requests per day. Here the valve had been in use for several months before the code was published on Github. During this time, it has demonstrated its stability, and has successfully limited the impact of DoS attacks by single or small groups of attacking computers.

# Commissioning

These are the steps to activate the valve:

1. Clone the project from Github and build the JAR with Maven 
2. Make the JAR available in Tomcat. Copy it for example into the same directory where your JDBC drivers are, which is probably `<CATALINA_HOME>/lib/`
3. In the `server.xml`, the valve must be configured inside the corresponding HOST element (see the example below)
4. Logging should be enabled so that at least messages about blocked accesses are logged (this is already the case in the standard configuration)

The valve is active now!

A test of the function can be carried out on a non-existent URL, to avoid any influence on the real applications. For the test, you set very low thresholds, and then performs quick reloads on the test address directly in the web browser until the valve blocks your requests. This sample configuration can be used for such a test:

        <Valve className="org.henbru.antidos.AntiDoSValve"
                alwaysAllowedIPs=""
                alwaysForbiddenIPs=""
                relevantPaths="/valvetest"
                maxIPCacheSize="50"
                numberOfSlots="10"
                slotLength="30"
                allowedRequestsPerSlot="5"
                shareOfRetainedFormerRequests="0"
        />
        
The test address is here `/valvetest` and from the 6th call access should be denied and a corresponding message should appear in the server log.

# Valve Configuration

The real challenge when commissioning the valve is to find the best settings for your server. The right balance must be found between too tight settings that would lock out your regular users, too loose settings that leave attackers untouched, and settings that hold too much data and thus unnecessarily load / slow down the Tomcat server.

In order to find the appropriate configuration you should make evaluations of the current server logs with the HTTP(S) requests, in particular to answer these questions:

* In which range are the normal access numbers per day / hour / minute / second? 
* What are the maximum values that can be attributed to individual IP addresses?
* Which IP addresses cause a lot of traffic? Which of these are internal services and which of search engines?
* Depending on the type of Tomcat application (s), it may make sense to make these evaluations differentiated for different parts of the applications. Access to static content such as images or stylesheets is usually less relevant than dynamic content
* How many requests does a users webbrowser generate when he visits your pages for the first time und of what kind are these requests? 

There are a number of logfile analysis tools that you can use for this purpose, but the usual unix tools like `grep`, `awk`, `sort`, `uniq` and `wc` will bring you very far. It is not neccessary to get a completely accurate picture (this varies probably anyway by the day), but to develop a basic sense of what is happening on your own server. If you have not generated any logfiles so far, it is now time to activate them.

In addition to the question of which usage pattern is displayed on the server in normal operation, an important point is the estimate of the access speed an attacker needs to cause overloads. The smaller the distance between regular server load and server overload, the more accurate the configuration of the Anti-DoS Valve must be.

Once the values have been determined you can develop the valve configuration, which is controlled by these parameters:

**alwaysForbiddenIPs**

An optional regular expression used to define IP addresses that are always blocked. This option and the following are _not part of the dynamic access rate limitation_ because they can completely block or always allow IP addresses.

Hint: You can use [this page (german)](http://www.regexplanet.com/advanced/java/index.html) to develop and test Java RegExps.

Hint 2: If you only want to use this option of the valve, you can use the [RemoteAddress Valve](https://tomcat.apache.org/tomcat-8.0-doc/config/valve.html#Remote_Address_Filter), which is already included in the Tomcat distribution.

**alwaysAllowedIPs**

An optional regular expression used to define IP addresses that are always allowed to access. This setting is only evaluated after _alwaysForbiddenIPs_.

This setting can, for example, be used to exclude accesses from your own intranet from a blockade so that no risk is created for internal users. If individual internal addresses are to be blocked later, this can be done via _alwaysForbiddenIPs_.

Both _alwaysForbiddenIPs_ and _alwaysAllowedIPs_ affect all requests that the Tomcat server processes. Accesses that are blocked or allowed in this way are not included in the access counts of the Anti-DoS Monitor.

**relevantPaths**

A regular expression used to define the URLs on which the Anti-DoS Monitor and thus the dynamic access rate limitation should take effect. The parameter is optional, but it will always be set if not only _alwaysForbiddenIPs_ is used by the function of the valve. Multiple important effects can be achieved with this option:

The access rate limitation can be restricted to applications or application parts which are actually used for concrete attacks. In servers that carry both public and non-public applications, monitoring can be restricted to the URLs that attackers can reach at all. In this way the Anti-DoS monitoring can be relieved and at the same time set more restrictive.

The access rate limitation can be restricted to application parts that actually cause a load, such as servlet calls. On the other hand, requests for static content, such as images and scripts, could be excluded. The exclusion of CSS, JavaScript and image files from Anti-DoS Monitoring can significantly reduce the risk of incorrect blocking of regular users.

Examples of parameter values:

* `".*"` With this pattern all requests will be handled by Anti-DoS Monitoring
* `"/manager.*"` With this pattern all requests to the Tomcat Manager App will be handled by the Anti-DoS Monitoring, but all other requests will be ignored

The following settings affect the dynamic access rate restriction in the Anti-DoS Monitor. The effects of these parameters partly influence each other:

**maxIPCacheSize**

Defines the maximum number of IP addresses considered in a slot. This number should be limited so that the memory requirements of the Anti-DoS monitor can not grow indefinitely. If this limit is exceeded, the addresses with the oldest requests are dropped first.

In this way, addresses which are actually relevant to the DoS defense are retained even in the case of small cache sizes, since they repeatedly move forward in the list due to their numerous accesses. Therefore, a comparatively small value can be set here.

**slotLength**

The length of a slot in seconds. An integer value greater than 0 must be set here. The duration of a slot and the _allowedRequestsPerSlot_ parameters are closely related:

**allowedRequestsPerSlot**

How many requests are permitted within a slot before an IP address is blocked. An integer value greater than 0 must be set here. As described above, the sum of the accesses counted in the slot and the accesses taken from previous slots are used for the check.

An increase in the duration of a slot (see _slotLength_) must be accompanied by an increase in the value entered here in order to minimize the risk of blocking regular users. However, a higher value increases the inertia of the monitor or the number of accesses that an attacker can perform before he is blocked.

A very small value of _slotLength_, on the other hand, reduces the advantages of using slots as the number of data to be stored is increased.

**numberOfSlots**

The number of slots the monitor should hold. Here, an integer value greater than 0 must be set. At a value of 1, the monitor would have no memory that goes beyond its current slot. Bigger values result in a larger 'memory' of the monitor.

This look back at the past is relevant when requests counted in previous slots are to be included in the evaluation of an IP address in the current slot. See the parameter _shareOfRetainedFormerRequests_. 

**shareOfRetainedFormerRequests**

This parameter defines the extent to which earlier requests from an IP address are used in their evaluation in the current slot. Here, a floating-point value greater than or equal to 0 must be set. To do this, the average value for an IP address observed in previous slots is calculated and this value is multiplied by the factor defined here. A higher value 'punishes' an IP address longer for previous offenses, a small value would allow an attacking IP address in each new slot to perform requests again. Examples of values:

* `0`: This value will not be used to transfer information from the past. In this case, the _numberOfSlots_ should be set to 1 to prevent unnecessary memory consumption.

* `0.5`: Here the half, average request number of the past would be taken over. A value less than 1 means that an attacker (but also an inadvertently blocked regular user) in a new slot initially has some accesses free again

* `1`: Here the average request number would be taken over completely. In the case of an ongoing DoS attack, an IP address, which has already made too many requests in all previous slots, would be blocked directly from the start of the new slot.

* `<NumberOfSlots>`: If the factor is set to the number of slots, then it would sufficient if an IP address had once too many accesses in the past to block it immediately in a new slot. Also a number of slots, in which the IP address has always been below the threshold, can eventually lead to a blockade. All values greater than 1 have this potential.

# Sample Configuration

The configuration shown above can be used as the starting point for the productive valve configuration.

You can run configuration values in this [**Google Drive Sheet**](https://docs.google.com/spreadsheets/d/1eztKVnzjW9xVVia1hDAeLaiiKRAGfNKRFx5lvKkbLBs/edit?usp=sharing). To do this, you must copy the sheet into your own Google Account and then edit the fields marked with **'set me!'**. Here, the impact of different configuration values on the access patterns of attackers (or regular users) can easily be watched.

Finally, the value for _relevantPaths_ must be developed. Here, if possible, only those parts of the applications that are accessible to attackers and which cause significant server loads should be covered.

# Monitoring

After the first commissioning, the valve should be closely monitored so that disturbances of regular users can be recognized and stopped early.

The corresponding entries are found in the Tomcat log files, entries of blocks can be found here via the keyword `AntiDoSMonitor`.

An alternative is monitoring with JMX, for example via `JConsole`. The internal states of the valve are visible via JMX and the settings of the valve can also be changed without restarting the server.
