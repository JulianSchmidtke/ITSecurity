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
catalinaHome = "/opt/tomcat/"
catalinaHomeBackup = catalinaHome + "backup/"
managerApplicationUtilized = True
# Username of the Tomcat admin
tomcatAdmin = 1002
# Group of tomcat users
tomcatGroup = 1001

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

def getAllFilePaths(directory): 
    # initializing empty file paths list 
    filePaths = [] 

    # crawling through directory and subdirectories 
    for root, directories, files in os.walk(directory): 
        for filename in files: 
            # join the two strings in order to form the full filepath. 
            filePath = os.path.join(root, filename) 
            filePaths.append(filePath) 
  
    # returning all file paths 
    return filePaths 

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
        os.remove(catalinaHome + 'conf/Catalina/localhost/manager.xml')

# 1.2  Disable Unused Connectors (Not Scored)
# Not Scored

# 2 Limit Server Platform Information Leaks
# Open and Unzip Jar
os.chdir(catalinaHome + 'lib/')
with ZipFile('catalina.jar', 'r') as zipObj:
    zipObj.extractall()

# Open serverinfo
serverInfoPropertiesPath = 'org/apache/catalina/util/ServerInfo.properties'
serverInfoProperties = Properties()
serverInfoProperties.load(open(serverInfoPropertiesPath))

# 2.1 Alter the Advertised server.info String (Scored)
serverInfoProperties['server.info'] = ''
# 2.2 Alter the Advertised server.number String (Scored)
serverInfoProperties['server.number'] = ''
# 2.3 Alter the Advertised server.built Date (Scored)
serverInfoProperties['server.built'] = ''

# save serverinfo
serverInfoProperties.store(open(serverInfoPropertiesPath, 'w'))
filePaths = getAllFilePaths('org/')
filePaths2 = getAllFilePaths('META-INF/')
with ZipFile('catalina.jar', 'w') as zipObj:
    for file in filePaths: 
        zipObj.write(file) 
    for file in filePaths2: 
        zipObj.write(file)
rmtree('org/')
rmtree('META-INF/')
os.chdir(catalinaHome)

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
elementTree.register_namespace('', "http://xmlns.jcp.org/xml/ns/javaee")
elementTree.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")
elementTree.register_namespace('schemaLocation', "http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd")
errorJSP = open(catalinaHome + 'conf/error.jsp', "w+")
errorJSP.write("<%@ page contentType=\"text/html;charset=UTF-8\" language=\"java\" %><%@ page isErrorPage=\"true\" %><!DOCTYPE html><html><head>    <title>Error Page</title></head><body><h1>An error has occurred.</h1><div style=\"color: #F00;\">    Error message: <%= exception.toString() %></div></body></html>")
errorJSP.close()

# 2.5 Disable client facing Stack Traces (Scored)
webTree = elementTree.parse(catalinaHome + '/conf/web.xml')
webRoot = webTree.getroot()
errorPage = elementTree.SubElement(webRoot, "error-page")
exceptionType = elementTree.SubElement(errorPage, "exception-type")
exceptionType.text = "java.lang.Throwable"
location = elementTree.SubElement(errorPage, "location")
location.text = "/error.jsp"

filter = elementTree.SubElement(webRoot, "filter")
filterName = elementTree.SubElement(filter, "filter-name")
filterName.text = "httpHeaderSecurity"
filterClass = elementTree.SubElement(filter, "filter-class")
filterClass.text = "org.apache.catalina.filters.HttpHeaderSecurityFilter"
initParam = elementTree.SubElement(filter, "init-param")
paramName = elementTree.SubElement(initParam, "param-name")
paramName.text = "antiClickJackingEnabled"
paramValue = elementTree.SubElement(initParam, "param-value")
paramValue.text = "true"

filterMapping = elementTree.SubElement(webRoot, "filter-mapping")
filterName = elementTree.SubElement(filterMapping, "filter-name")
filterName.text = "httpHeaderSecurity"
urlPattern = elementTree.SubElement(filterMapping, "url-pattern")
urlPattern.text = "/*"

webTree.write(catalinaHome + '/conf/web.xml')

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
serviceElements = serverRoot.findall('Service')
for serviceElement in serviceElements:
    engineElements = serviceElement.findall('Engine')
    for engineElement in engineElements:
        realmElement = engineElement.find('Realm')
        realmElement.set("className", "org.apache.catalina.realm.LockOutRealm")
        realmElement.set("failureCount", "3")
        realmElement.set("lockoutTime", "600")
        realmElement.set("cacheSize", "1000")
        realmElement.set("cacheRemovalWarningTime", "3600")

serverTree.write(catalinaHome + '/conf/server.xml')

# 6 Connector Security
# 6.1 Setup Client-cert Authentication (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
connectors = findElementsByTagname(serverRoot, 'Connector')
for connector in connectors:
    connector.set("clientAuth", "true") 
serverTree.write(catalinaHome + '/conf/server.xml')
# 6.2 Ensure SSLEnabled is set to True for Sensitive Connectors (Not Scored)
# Not Scored
# 6.3 Ensure scheme is set accurately (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
connectors = findElementsByTagname(serverRoot, 'Connector')
for connector in connectors:
    if connector.get('protocol') > "HTTPS":
        connector.set("scheme", "https") 
    else:
        connector.set("scheme", "http") 

serverTree.write(catalinaHome + '/conf/server.xml')
# 6.4 Ensure secure is set to true only for SSL-enabled Connectors (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
connectors = findElementsByTagname(serverRoot, 'Connector')
for connector in connectors:
    if connector.get('SSLEnabled') == "True":
        connector.set("secure", "true") 
    else:
        connector.set("secure", "false") 
        
serverTree.write(catalinaHome + '/conf/server.xml')
# 6.5 Ensure SSL Protocol is set to TLS for Secure Connectors (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
connectors = findElementsByTagname(serverRoot, 'Connector')
for connector in connectors:
    if connector.get('SSLEnabled') == "True":
        connector.set("sslProtocol", "TLS") 
serverTree.write(catalinaHome + '/conf/server.xml')

# 7 Establish and Protect Logging Facilities
# 7.1 Application specific logging (Scored)
sourceLoggingPorperties = catalinaHome + '/conf/logging.properties'
webAppsDir = catalinaHome + 'webapps/'

dirs = os.listdir(webAppsDir)

for dir in dirs:
    dstLoggingPropertiesDir = webAppsDir + dir + '/WEB-INF/classes/'
    if not os.path.exists(dstLoggingPropertiesDir):
        os.mkdir(dstLoggingPropertiesDir)
    dstLoggingPropertiesPath = dstLoggingPropertiesDir + '/logging.properties'
    copy2(sourceLoggingPorperties, dstLoggingPropertiesPath)
    # 7.2 Specify file handler in logging.properties files (Scored)
    handlerLine = "handlers = 1catalina.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler"
    logfile = open(dstLoggingPropertiesPath)
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

    new_logfile = open(dstLoggingPropertiesPath, 'w')
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
            valve.set("directory", "$CATALINA_HOME/logs/")
            valve.set("prefix", "access_log")
            valve.set("fileDateFormat", "yyyy-MM-dd.HH")
            valve.set("suffix", ".log")
            valve.set("pattern", "%t %H cookie:%{SESSIONID}c request:%{SESSIONID}r %m %U %s %q %r")
        serverTree.write(contextXMLFile)

# 7.4 also
os.chown(catalinaHome + "/logs", tomcatAdmin, tomcatGroup)
os.chmod(catalinaHome + "/logs", groupRemoveWriteWorldRemoveAll)

# 8 Configure Catalina Policy
# 8.1 Restrict runtime access to sensitive packages (Scored)
catalinaConf = catalinaHome + '/conf/catalina.properties'
packageLine = """package.access = sun.,org.apache.catalina.,
    org.apache.coyote.,org.apache.tomcat., org.apache.jasper"""
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
# TODO add -security to tomcat startup scrip in /etc/init.d

# 9.2 Disabling auto deployment of applications (Scored)
serverXMLFile = catalinaHome + 'conf/server.xml'
if os.path.exists(serverXMLFile):
    serverTree = elementTree.parse(serverXMLFile)
    serverRoot = serverTree.getroot()
    serviceElements = serverRoot.findall('Service')
    for serviceElement in serviceElements:
        engineElements = serviceElement.findall('Engine')
        for engineElement in engineElements:
            hostElement = engineElement.find('Host')
            if hostElement.get("autoDeploy") == "true":
                hostElement.set("autoDeploy", "false")
            # 9.3 Disable deploy on startup of applications (Scored)
            hostElement.set("deployOnStartup", "true")
    serverTree.write(serverXMLFile)

# 10 Miscellaneous Configuration Settings
# 10.1 Ensure Web content directory is on a separate partition from the Tomcat
# system files (Not Scored)
# Not Scored
# 10.2 Restrict access to the web administration (Not Scored)
# Not Scored
# 10.3 Restrict manager application (Not Scored)
# Not Scored
# 10.4 Force SSL when accessing the manager application (Scored)
# Haben wir nicht
# 10.5 Rename the manager application (Scored)
# Haben wir nicht
# 10.6 Enable strict servlet Compliance (Scored)
# TODO:
# 10.7 Turn off session façade recycling (Scored)
# TODO
# 10.8 Do not allow additional path delimiters (Scored)
# Standardmäßig deaktiviert
# 10.9 Do not allow custom header status messages (Scored)
# Standardmäßig deaktiviert
# 10.10 Configure connectionTimeout (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
connectors = findElementsByTagname(serverRoot, 'Connector')
for connector in connectors:
    connector.set("connectionTimeout", "60000")
serverTree.write(catalinaHome + '/conf/server.xml')
# 10.11 Configure maxHttpHeaderSize (Scored)
# Standardmäßig deaktiviert
# 10.12 Force SSL for all applications (Scored)
# TODO: Wir haben noch gar kein Security Constraint
# 10.13 Do not allow symbolic linking (Scored)
# Standardmäßig deaktiviert
# 10.14 Do not run applications as privileged (Scored)
# Standardmäßig deaktiviert
# 10.15 Do not allow cross context requests (Scored)
# Standardmäßig deaktiviert
# 10.16 Do not resolve hosts on logging valves (Scored)
# Standardmäßig deaktiviert
# 10.17 Enable memory leak listener (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
leakPreventionListener = elementTree.SubElement(serverRoot, 'Listener')
leakPreventionListener.set("className", "org.apache.catalina.core.JreMemoryLeakPreventionListener")
serverTree.write(catalinaHome + '/conf/server.xml')
# 10.18 Setting Security Lifecycle Listener (Scored)
serverTree = elementTree.parse(catalinaHome + '/conf/server.xml')
serverRoot = serverTree.getroot()
securityListener = elementTree.SubElement(serverRoot, 'Listener')
securityListener.set("className", "org.apache.catalina.security.SecurityListener")
securityListener.set("checkedOsUsers", "root")
securityListener.set("minimumUmask", "0007")
serverTree.write(catalinaHome + '/conf/server.xml')
# 10.19 use the logEffectiveWebXml and metadata-complete settings for deployingapplications in production (Scored)
webAppsDir = catalinaHome + '/webapps/'
dirs = os.listdir(webAppsDir)
for dir in dirs:
    dstDir = webAppsDir + dir + '/WEB-INF'
    elementTree.register_namespace('', "http://xmlns.jcp.org/xml/ns/javaee")
    elementTree.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")
    elementTree.register_namespace('schemaLocation', "http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd")
    serverTree = elementTree.parse(dstDir + '/web.xml')
    serverRoot = serverTree.getroot()
    serverRoot.set('metadata-complete', 'true')
    serverTree.write(dstDir + '/web.xml')