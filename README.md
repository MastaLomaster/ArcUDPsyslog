### Purpose
The program forwards **Arcserve UDP** activity log messages using syslog protocol.
This allows to monitor the backup processes using popular systems monitoring tools.

### Features and requirements

- Sends messages every 90 seconds, minimal footprint and system load
- Works with Arcserve UDP versions 8.X, 7.X (and probably 6.X - lacking MessageID field)
- Can filter the messages before sending, based on severity (e.g., send only errors and warnings)
- Supported message formats: RFC3164 RFC5424
- Runs as a service on the Arcserve UDP console node with the local MS SQL Express database
- Can send syslog messages using UDP datagram protocol only, TCP is not supported

### Installation 

The program can be installed on Arcserve UDP console node with the local SQL [Express] database only. 
1. Create some directory for the program, for example C:\ArcUDPsyslog\
2. Download and unzip the [ArcUDPsyslog.zip](https://github.com/MastaLomaster/ArcUDPsyslog/raw/master/ArcUDPsyslog.zip) to this directory:
![](http://arcserve.su/as/01.png)

3. In the elevated command prompt (Run as Administrator) execute:
**C:\ArcUDPsyslog\ArcUDPsyslog -install**
![](http://arcserve.su/as/02.png)

4. Make sure the service is created:
![](http://arcserve.su/as/03.png)

5. Grant the NT AUTHORITY/SYSTEM sysadmin server role in the SQL Express database server:
![](http://arcserve.su/as/04.png)

6.  Edit the ArcUDPsyslog.cfg file and specify the IP address and port of the node you are going to forward log messages. Also specify the correct message format:
![](http://arcserve.su/as/05.png)

7. Start the service
8. Enjoy!

### Screenshots
Arcserve UDP log messages in Nagios:
![](http://arcserve.su/as/06.png)

Arcserve UDP messages in EZ5 Syslog Watcher:
![](http://arcserve.su/as/07.png)

Arcserve UDP messages in linux rsyslog:
![](http://arcserve.su/as/08.png)


