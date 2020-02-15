#!/usr/bin/python3

from shutil import copyfile, rmtree
import xml.etree.ElementTree as elementTree
import os
import configparser

# Global Variables
# Path to the apache root directory
catalinaHome = ""  # /home/lukas/apache-tomcat-8.5.37/
catalinaHomeBackup = catalinaHome + "backup/"
managerApplicationUtilized = False

# Global Functions


def backupFiles(sourceRoot, targetRoot, path):
    copyfile(sourceRoot + path,
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
backupFiles(catalinaHome, catalinaHomeBackup, 'webapps/docs')
backupFiles(catalinaHome, catalinaHomeBackup, 'webapps/examples')
backupFiles(catalinaHome, catalinaHomeBackup, 'webapps/host-manager')
backupFiles(catalinaHome, catalinaHomeBackup, 'webapps/manager')
backupFiles(catalinaHome, catalinaHomeBackup,
            'conf/Catalina/localhost/manager.xml')
backupFiles(catalinaHome, catalinaHomeBackup, 'conf/server.xml')
backupFiles(catalinaHome, catalinaHomeBackup, 'lib/')

# 1 Remove Extraneous Resources
# 1.1 Remove extraneous files and directories (Scored)
rmtree(catalinaHome + 'webapps/docs')
rmtree(catalinaHome + 'webapps/examples')

if not managerApplicationUtilized:
    rmtree(catalinaHome + 'webapps/host-manager')
    rmtree(catalinaHome + 'webapps/manager')
    rmtree(catalinaHome + 'conf/Catalina/localhost/manager.xml')

# 1.2  Disable Unused Connectors (Not Scored)

# 2 Limit Server Platform Information Leaks
# Open and Unzip Jar
# TODO: Extract JAR
os.chdir(catalinaHome + '\lib')

# Open serverinfo
serverInfoProperties = configparser.RawConfigParser()
serverInfoProperties.read(catalinaHome + '/lib/org/apache/catalina/util/ServerInfo.properties','w+')

# TODO: Passen die Werte?
# 2.1 Alter the Advertised server.info String (Scored)
serverInfoProperties['server.info'] = ''
# 2.2 Alter the Advertised server.number String (Scored)
serverInfoProperties['server.number'] = ''
# 2.3 Alter the Advertised server.built Date (Scored)
serverInfoProperties['server.built'] = ''

# save serverinfo
serverInfoProperties.write(catalinaHome + '/lib/org/apache/catalina/util/ServerInfo.properties')

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
# TODO:
# 4.1 Restrict access to $CATALINA_HOME (Scored)
# 4.2 Restrict access to $CATALINA_BASE (Scored)
# 4.3 Restrict access to Tomcat configuration directory (Scored)
# 4.4 Restrict access to Tomcat logs directory (Scored)
# 4.5 Restrict access to Tomcat temp directory (Scored)
# 4.6 Restrict access to Tomcat binaries directory (Scored)
# 4.7 Restrict access to Tomcat web application directory (Scored)
# 4.8 Restrict access to Tomcat catalina.policy (Scored)
# 4.9 Restrict access to Tomcat catalina.properties (Scored)
# 4.10 Restrict access to Tomcat context.xml (Scored)
# 4.11 Restrict access to Tomcat logging.properties (Scored)
# 4.12 Restrict access to Tomcat server.xml (Scored)
# 4.13 Restrict access to Tomcat tomcat-users.xml (Scored)
# 4.14 Restrict access to Tomcat web.xml (Scored)

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
# 7.2 Specify file handler in logging.properties files (Scored)
# 7.3 Ensure className is set correctly in context.xml (Scored)
# 7.4 Ensure directory in context.xml is a secure location (Scored)
# 7.5 Ensure pattern in context.xml is correct (Scored)
# 7.6 Ensure directory in logging.properties is a secure location (Scored)
# 7.7 Configure log file size limit (Scored)

# 8 Configure Catalina Policy
# 8.1 Restrict runtime access to sensitive packages (Scored)

# 9 Application Deployment
# 9.1 Starting Tomcat with Security Manager (Scored)
# 9.2 Disabling auto deployment of applications (Scored)
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
