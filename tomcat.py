#!/usr/bin/python3

from shutil import copy2, copyfile, copytree, rmtree
from zipfile import ZipFile
from pyjavaproperties import Properties
import xml.etree.ElementTree as elementTree
import os
import configparser
import re

# Global Variables
# Path to the apache root directory
catalinaHome = "C:/Users/Julian/Desktop/apache-tomcat-8.5.51/"
catalinaHomeBackup = catalinaHome + "backup/"
managerApplicationUtilized = False
# Username of the Tomcat admin
tomcatAdmin = "tomcat_admin"
# Group of tomcat users
tomcatGroup = "tomcat"

# Global Functions


def backupFile(sourceRoot, targetRoot, path):
    if os.path.exists(sourceRoot + path) and not os.path.exists(targetRoot + path):
        copyfile(sourceRoot + path,
                 targetRoot + path)


def backupFolder(sourceRoot, targetRoot, path):
    if os.path.exists(sourceRoot + path) and not os.path.exists(targetRoot + path):
        copytree(sourceRoot + path,
                 targetRoot + path)


def findElementsByTagname(root, tagname):
    elements = []
    if not root:
        return []

    for child in root:
        elements.extend(findElementsByTagname(child, tagname))
    new_elements = root.findall(tagname)

    elements.extend(new_elements)
    return elements


# Backup
backupFolder(catalinaHome, catalinaHomeBackup, 'webapps/docs/')
backupFolder(catalinaHome, catalinaHomeBackup, 'conf/')
backupFolder(catalinaHome, catalinaHomeBackup, 'lib/')

# 1 Remove Extraneous Resources
# 1.1 Remove extraneous files and directories (Scored)
if os.path.exists(catalinaHome + 'webapps/docs/'):
    rmtree(catalinaHome + 'webapps/docs/')
if os.path.exists(catalinaHome + 'webapps/examples/'):
    rmtree(catalinaHome + 'webapps/examples/')

if not managerApplicationUtilized:
    if os.path.exists(catalinaHome + 'webapps/host-manager/'):
        rmtree(catalinaHome + 'webapps/host-manager/')
    if os.path.exists(catalinaHome + 'webapps/manager/'):
        rmtree(catalinaHome + 'webapps/manager/')
    if os.path.exists(catalinaHome + 'conf/Catalina/localhost/manager.xml'):
        rmtree(catalinaHome + 'conf/Catalina/localhost/manager.xml')

# 1.2  Disable Unused Connectors (Not Scored)

# 2 Limit Server Platform Information Leaks
# Open and Unzip Jar
os.chdir(catalinaHome + 'lib/')
with ZipFile('catalina.jar', 'r') as zipObj:
    zipObj.extractall()

# Open serverinfo
serverInfoProperties = Properties()
serverInfoProperties.load(open(
    catalinaHome + 'lib/org/apache/catalina/util/ServerInfo.properties'))

# 2.1 Alter the Advertised server.info String (Scored)
serverInfoProperties['server.info'] = ''
# 2.2 Alter the Advertised server.number String (Scored)
serverInfoProperties['server.number'] = ''
# 2.3 Alter the Advertised server.built Date (Scored)
serverInfoProperties['server.built'] = ''

# save serverinfo
serverInfoProperties.store(open(
    catalinaHome + 'lib/org/apache/catalina/util/ServerInfo.properties', 'w'))

# TODO: Save and Zip Jar


# 2.4 Disable X-Powered-By HTTP Header and Rename the Server Value for all
# Connectors (Scored)
# Get server.xml
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
# Change connectors
connectors = findElementsByTagname(serverRoot, 'Connector')
for connector in connectors:
    connector.set("xpoweredBy", "false")
    connector.set("server", "NotABlankString")
# Save server.xml
serverTree.write(catalinaHome + '/conf/server.xml')

# 2.5 Disable client facing Stack Traces (Scored)
# TODO:

# 2.6 Turn off TRACE (Scored)
# Get server.xml
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
# Change connectors
connectors = findElementsByTagname(serverRoot, 'Connector')
for connector in connectors:
    connector.set("allowTrace", "false")
# Save server.xml
serverTree.write(catalinaHome + '/conf/server.xml')


# 3 Protect the Shutdown Port
# Get server.xml
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()

# 3.1 Set a nondeterministic Shutdown command value (Scored)
serverRoot.set('shutdown', 'WpoLHtGukHEji83KhbSX')  # Random String

# 3.2 Disable the Shutdown port (Not Scored)
serverRoot.set('port', '-1')

# Save server.xml
serverTree.write(catalinaHome + '/conf/server.xml')

# 4 Protect Tomcat Configurations
# Group no Write, World no Permission at all
groupRemoveWriteWorldRemoveAll = 0o750  # g-w, o-rwx
worldRemoveAll = 0o770  # o-rwx

# 4.1 Restrict access to $CATALINA_HOME (Scored)
os.chown(catalinaHome, tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome, groupRemoveWriteWorldRemoveAll)
# chmod g-w,o-rwx $CATALINA_HOME

# 4.2 Restrict access to $CATALINA_BASE (Scored)
# Not used

# 4.3 Restrict access to Tomcat configuration directory (Scored)
os.chown(catalinaHome + '/conf/', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/conf/', groupRemoveWriteWorldRemoveAll)

# 4.4 Restrict access to Tomcat logs directory (Scored)
os.chown(catalinaHome + '/logs/', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/logs/', worldRemoveAll)

# 4.5 Restrict access to Tomcat temp directory (Scored)
os.chown(catalinaHome + '/temp/', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/temp/', worldRemoveAll)

# 4.6 Restrict access to Tomcat binaries directory (Scored)
os.chown(catalinaHome + '/bin/', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/bin/', worldRemoveAll)

# 4.7 Restrict access to Tomcat web application directory (Scored)
os.chown(catalinaHome + '/webapps/', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/webapps/', worldRemoveAll)

# 4.8 Restrict access to Tomcat catalina.policy (Scored)
os.chown(catalinaHome + '/conf/catalina.policy', tomcatAdmin, tomcatGroup)

# 4.9 Restrict access to Tomcat catalina.properties (Scored)
os.chown(catalinaHome + '/conf/catalina.properties', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/conf/catalina.properties',
         groupRemoveWriteWorldRemoveAll)

# 4.10 Restrict access to Tomcat context.xml (Scored)
os.chown(catalinaHome + '/conf/context.xml', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/conf/context.xml', groupRemoveWriteWorldRemoveAll)

# 4.11 Restrict access to Tomcat logging.properties (Scored)
os.chown(catalinaHome + '/conf/logging.properties', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/conf/logging.properties',
         groupRemoveWriteWorldRemoveAll)

# 4.12 Restrict access to Tomcat server.xml (Scored)
os.chown(catalinaHome + '/conf/server.xml', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/conf/server.xml', groupRemoveWriteWorldRemoveAll)

# 4.13 Restrict access to Tomcat tomcat-users.xml (Scored)
os.chown(catalinaHome + '/conf/tomcat-users.xml', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/conf/tomcat-users.xml',
         groupRemoveWriteWorldRemoveAll)

# 4.14 Restrict access to Tomcat web.xml (Scored)
os.chown(catalinaHome + '/conf/web.xml', tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + '/conf/web.xml', groupRemoveWriteWorldRemoveAll)

# 5 Configure Realms
# 5.1 Use secure Realms (Scored)
# TODO:
# 5.2 Use LockOut Realms (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
realmElement = serverRoot.find('Realm')
realmElement.set("className", "org.apache.catalina.realm.LockOutRealm")
realmElement.set("failureCount", "3")
realmElement.set("lockoutTime", "600")
realmElement.set("cacheSize", "1000")
realmElement.set("cacheRemovalWarningTime", "3600")
serverTree.write(catalinaHome + '/conf/server.xml')

# 6 Connector Security
# TODO:
# 6.1 Setup Client-cert Authentication (Scored)
# 6.2 Ensure SSLEnabled is set to True for Sensitive Connectors (Not Scored)
# 6.3 Ensure scheme is set accurately (Scored)
# 6.4 Ensure secure is set to true only for SSL-enabled Connectors (Scored)
# 6.5 Ensure SSL Protocol is set to TLS for Secure Connectors (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
connectors = findElementsByTagname(serverRoot, 'Connector')
for connector in connectors:
    if connector.get('SSLEnabled') == True:
        connector.set("sslProtocol", "TLS")
serverTree.write(catalinaHome + '/conf/server.xml')

# 7 Establish and Protect Logging Facilities
# 7.1 Application specific logging (Scored)
sourceLoggingPorperties = catalinaHome + '/conf/logging.properties'
webAppsDir = catalinaHome + '/webapps/'

dirs = os.listdir(webAppsDir)

for dir in dirs:
    dstLoggingPropertiesDir = webAppsDir + dir + '/WEB-INF/classes'
    if not os.path.exists(dstLoggingPropertiesDir):
        os.mkdir(dstLoggingPropertiesDir)
    dstLoggingPropertiesDir = dstLoggingPropertiesDir + '/logging.properties'
    copy2(sourceLoggingPorperties, dstLoggingPropertiesDir)
    # 7.2 Specify file handler in logging.properties files (Scored)
    handlerLine = "handlers = 1catalina.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler"
    logfile = open(dstLoggingPropertiesDir)
    loglist = logfile.readlines()
    logfile.close()
    if handlerLine not in loglist:
        loglist.append(handlerLine)
    # 7.6 Ensure directory in logging.properties is a secure location (Scored)
    logFileLoc = webAppsDir + dir + '/WEB-INF/'
    logLocLine = dir + ".org.apache.juli.FileHandler.directory=" + logFileLoc
    if logLocLine not in loglist:
        loglist.append(logLocLine)
    appNameLine = dir + ".org.apache.juli.FileHandler.prefix=" + dir
    if appNameLine not in loglist:
        loglist.append(appNameLine)
    # 7.7 Configure log file size limit (Scored)
    loglist.append("java.util.logging.FileHandler.limit=10000")

    new_logfile = open(dstLoggingPropertiesDir, 'w')
    for lines in loglist:
        new_logfile.write(lines)

    # 7.6 also
    os.chown(logFileLoc, tomcatAdmin, tomcatGroup)
    os.chmod(logFileLoc, groupRemoveWriteWorldRemoveAll)

    # 7.3 Ensure className is set correctly in context.xml (Scored)
    contextXMLFile = webAppsDir + dir + '/META-INF/context.xml'
    if os.path.exists(contextXMLFile):
        serverTree = elementTree.parse(contextXMLFile)
        serverRoot = serverTree.getroot()
        valves = findElementsByTagname(serverRoot, 'Valve')
        for valve in valves:
            if valve.get("className") == "org.apache.catalina.valves.RemoteAddrValve":
                valve.set("className", 'org.apache.catalina.valves.AccessLogValve')
        # 7.4 Ensure directory in context.xml is a secure location (Scored)
        # 7.5 Ensure pattern in context.xml is correct (Scored)
        valveElement = serverRoot.find("Valve")
        valveElement.set("directory", "$CATALINA_HOME/logs/")
        valveElement.set("prefix", "access_log")
        valveElement.set("fileDateFormat", "yyyy-MM-dd.HH")
        valveElement.set("suffix", ".log")
        valveElement.set("pattern", "%t %H cookie:%{SESSIONID}c request:%{SESSIONID}r %m %U %s %q %r")
        serverTree.write(contextXMLFile)

# 7.4 also
os.chown(catalinaHome + "/logs", tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + "/logs", groupRemoveWriteWorldRemoveAll)

# 8 Configure Catalina Policy
# 8.1 Restrict runtime access to sensitive packages (Scored)
catalinaConf = catalinaHome + '/conf/catalina.properties'
packageLine = "package.access = sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat., org.apache.jasper"
logfile = open(catalinaConf)
loglist = logfile.readlines()
logfile.close()
if packageLine not in loglist:
    loglist.append(packageLine)

new_logfile = open(catalinaConf, 'w')
for lines in loglist:
    new_logfile.write(lines)

# 9 Application Deployment
# 9.1 Starting Tomcat with Security Manager (Scored)
# add -security to tomcat startup scrip in /etc/init.d
#engine -> host -> service -> root autoDeploy = false
# 9.2 Disabling auto deployment of applications (Scored)
serverXMLFile = catalinaHome + '/conf/server.xml'
if os.path.exists(serverXMLFile):
    serverTree = elementTree.parse(serverXMLFile)
    serverRoot = serverTree.getroot()
    service = findElementsByTagname(serverRoot, 'Service')
    engine = findElementsByTagname(service, 'Engine')
    hosts = findElementsByTagname(engine, 'Host')
    for host in hosts:
        if host.get("autoDeploy") == "true":
            host.set("autoDeploy", 'false')

# 9.3 Disable deploy on startup of applications (Scored)

# 10 Miscellaneous Configuration Settings
# 10.1 Ensure Web content directory is on a separate partition from the Tomcat
# system files (Not Scored)
# 10.2 Restrict access to the web administration (Not Scored)
# 10.3 Restrict manager application (Not Scored)
# 10.4 Force SSL when accessing the manager application (Scored)
# 10.5 Rename the manager application (Scored)
# 10.6 Enable strict servlet Compliance (Scored)
# 10.7 Turn off session façade recycling (Scored)
# 10.8 Do not allow additional path delimiters (Scored)
# 10.9 Do not allow custom header status messages (Scored)
# 10.10 Configure connectionTimeout (Scored)
# 10.11 Configure maxHttpHeaderSize (Scored)
# 10.12 Force SSL for all applications (Scored)
# 10.13 Do not allow symbolic linking (Scored)
# 10.14 Do not run applications as privileged (Scored)
# 10.15 Do not allow cross context requests (Scored)
# 10.16 Do not resolve hosts on logging valves (Scored)
# 10.17 Enable memory leak listener (Scored)
# 10.18 Setting Security Lifecycle Listener (Scored)
# 10.19 use the logEffectiveWebXml and metadata-complete settings for deployingapplications in production (Scored)
