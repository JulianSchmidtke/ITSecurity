#!/usr/bin/python3
import os, sys, stat, shutil, configparser, xml.etree.ElementTree as et
from jproperties import Properties
from shutil import copyfile

print("Kopieren der OriginalDateien als Backup")

copyfile('/home/lukas/apache-tomcat-8.5.37/conf/server.xml','/home/lukas/apache-tomcat-8.5.37/conf/serverkopie.xml')
copyfile('/home/lukas/apache-tomcat-8.5.37/bin/catalina.sh','/home/lukas/apache-tomcat-8.5.37/bin/catalinakopie.xml')
copyfile('/home/lukas/apache-tomcat-8.5.37/lib/org/apache/catalina/util/ServerInfo.properties','/home/lukas/apache-tomcat-8.5.37/lib/org/apache/catalina/util/ServerInfokopie.properties')
copyfile('/home/lukas/apache-tomcat-8.5.37/conf/logging.properties','/home/lukas/apache-tomcat-8.5.37/conf/loggingkopie.properties')
copyfile('/home/lukas/apache-tomcat-8.5.37/webapps/nochmalanders/META-INF/context.xml','/home/lukas/apache-tomcat-8.5.37/webapps/nochmalanders/META-INF/contextkopie.xml')
copyfile('/home/lukas/apache-tomcat-8.5.37/webapps/host-manager/META-INF/context.xml','/home/lukas/apache-tomcat-8.5.37/webapps/host-manager/META-INF/contextkopie.xml')


new_lines = [
    'JAVA_OPTS="$JAVA_OPTS -Dorg.apache.catalina.STRICT_SERVLET_COMPLIANCE=true"',
    'JAVA_OPTS="$JAVA_OPTS -Dorg.apache.catalina.connector.RECYCLE_FACADES=true"',
    'JAVA_OPTS="$JAVA_OPTS -Dorg.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH=false"',
    'JAVA_OPTS="$JAVA_OPTS -Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=false"',
    'JAVA_OPTS="$JAVA_OPTS -Dorg.apache.coyote.USE_CUSTOM_STATUS_MSG_IN_HEADER=false"'
]

catalina_sh = open('/home/lukas/apache-tomcat-8.5.37/bin/catalina.sh', 'w+')
catalina_sh_lines = catalina_sh.readlines()
position = 2
print(new_lines)
catalina_sh_lines[position:position] = new_lines
with open('/home/lukas/apache-tomcat-8.5.37/bin/catalina-test.sh', 'w+') as outf:
    outf.write('\n'.join(catalina_sh_lines))

tree = et.parse('/home/lukas/apache-tomcat-8.5.37/conf/server.xml')
root = tree.getroot()
root.set("shutdown","herunterfahren")

print (root.tag, root.attrib)
errorseite = et.SubElement(root, "error-page")
errorseitesub = et.SubElement(errorseite, "exception-type")
errorseitesub2 =et.SubElement(errorseite, "location")
errorseitesub.text = "java.lang.Throwable"
errorseitesub2.text = "error.jsp"

securitylistener = et.SubElement(root, "Listener")
securitylistener.set("className", "org.apache.catalina.security.SecurityListener")
securitylistener.set("checkedOSUsers", "")
securitylistener.set("minimumUmask", "007")

def find_elements_by_tagname(root, tagname):
    elements = []
    if not root:
        return []

    for child in root:
        elements.extend(find_elements_by_tagname(child, tagname))
    new_elements = root.findall(tagname)

    elements.extend(new_elements)
    return elements

connectors = find_elements_by_tagname(root, 'Connector')
connectors[0].set("connectionTimeout", "60000")
connectors[0].set("scheme", "http")
connectors[0].set("allowTrace", "false")
connectors[1].set("allowTrace", "false")
connectors[0].set("xpoweredBy", "false")
connectors[1].set("xpoweredBy", "false")
connectors[0].set("adress", "0.0.0.0")

hosts = find_elements_by_tagname(root, 'Host')
hosts[0].set("autoDeploy","false")
        
for child in root:
    print ("child")
    print(child.tag, child.attrib)
    for subchild in child:
        print ("subchild")
        print(subchild.tag,subchild.attrib)
        for element in subchild:
            print ("element")
lockoutrealm = et.SubElement(element, "Realm")
lockoutrealm.set("className", "org.apache.catalina.realm.LockOutRealm")
lockoutrealm.set("failureCount", "3")
lockoutrealm.set("lockoutTime", "600")
lockoutrealm.set("cacheSize", "1000") 
lockoutrealm.set("cacheRemovalWarningTime", "3600")

for subelement in element:
    print ("subelement")
    print (subelement.tag, subelement.attrib)

tree.write('/home/lukas/apache-tomcat-8.5.37/conf/server.xml')

serverinfo = open ('/home/lukas/apache-tomcat-8.5.37/lib/org/apache/catalina/util/ServerInfo.properties','w+')
p = Properties()
p.load(source_data=serverinfo.read())
p['server.info'] = 'Apache Tomcat'
p['server.number'] = 'Servernummer'
p['server.built'] = 'Servererstellt'
serverinfo.write('/home/lukas/apache-tomcat-8.5.37/lib/org/apache/catalina/util/ServerInfo.properties')

logging = open ('/home/lukas/apache-tomcat-8.5.37/conf/logging.properties','w+')
l = Properties()
l.load(source_data=logging.read())
l['handlers'] = '1catalina.org.apache.juli.AsyncFileHandler, 2localhost.org.apache.juli.AsyncFileHandler, 3manager.org.apache.juli.AsyncFileHandler, 4host-manager.org.apache.juli.AsyncFileHandler, java.util.logging.ConsoleHandler/handlers = 1catalina.org.apache.juli.AsyncFileHandler, 2localhost.org.apache.juli.AsyncFileHandler, 3manager.org.apache.juli.AsyncFileHandler, 4host-manager.org.apache.juli.AsyncFileHandler, 5org.apache.juli.FileHandler, java.util.logging.ConsoleHandler /home/lukas/apache-tomcat-8.5.37/webapps/examples/WEB-INF/classes/logging.properties'
l['org.apache.juli.FileHandler.leve'] = 'FINEST'
l['java.util.logging.FileHandler.limit'] = '10000'

logging.write('/home/lukas/apache-tomcat-8.5.37/conf/logging.properties')

print ("context.xml")

baum = et.parse('/home/lukas/apache-tomcat-8.5.37/webapps/nochmalanders/META-INF/context.xml')
reet = baum.getroot()

valve = et.SubElement(reet, "Valve") 
valve.set("className", "org.apache.catalina.valves.AccessLogValve")
valve.set("directory", "/home/lukas/apache-tomcat-8.5.37/logs/")
valve.set("prefix", "access_log")
valve.set("fileDateFormat", "yyyy-MM-dd.HH")
valve.set("suffix", ".log")
valve.set("pattern", "%t %H cookie:%{SESSIONID}c request:%{SESSIONID}r %m %U %s %q %r")

resource = et.SubElement(reet, "Resources")
resource.set("allowLinking", "false")

reet.set("privileged", "false")
reet.set("crossContext", "false")
reet.set("logEffectiveWebXml", "true")
print(reet.tag, reet.attrib)

for child in reet:
    print ("child")
    print(child.tag, child.attrib)
    for subchild in child:
        print ("subchild")
        print(subchild,subchild.tag,subchild.attrib)

baum.write('/home/lukas/apache-tomcat-8.5.37/webapps/nochmalanders/META-INF/context.xml')

print ("context2.xml")
baum2 = et.parse('/home/lukas/apache-tomcat-8.5.37/webapps/host-manager/META-INF/context.xml')
reet2 = baum2.getroot()

valve = et.SubElement(reet2, "Valve") 
valve.set("className", "org.apache.catalina.valves.AccessLogValve")
valve.set("directory", "/home/lukas/apache-tomcat-8.5.37/logs/")
valve.set("prefix", "access_log")
valve.set("fileDateFormat", "yyyy-MM-dd.HH")
valve.set("suffix", ".log")
valve.set("pattern", "%t %H cookie:%{SESSIONID}c request:%{SESSIONID}r %m %U %s %q %r")

resource = et.SubElement(reet2, "Resources")
resource.set("allowLinking", "false")

reet2.set("privileged", "false")
reet2.set("crossContext", "false")
reet2.set("logEffectiveWebXml", "true")
print(reet2.tag, reet2.attrib)


for child in reet2:
    print ("child")
    print(child.tag, child.attrib)
    for subchild in child:
        print ("subchild")
        print(subchild,subchild.tag,subchild.attrib)

baum2.write('/home/lukas/apache-tomcat-8.5.37/webapps/host-manager/META-INF/context.xml')


gruppe = 0o750 #g-w und o-rwx
andere = 0o770 #o-rwx
restrictions = {
    '/home/lukas/apache-tomcat-8.5.37' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/conf' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/logs' : andere,
    '/home/lukas/apache-tomcat-8.5.37/temp' : andere,
    '/home/lukas/apache-tomcat-8.5.37/bin' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/webapps' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/conf/catalina.policy' : andere,
    '/home/lukas/apache-tomcat-8.5.37/conf/catalina.properties' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/conf/context.xml' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/conf/logging.properties' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/conf/server.xml' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/conf/tomcat-users.xml' : gruppe,
    '/home/lukas/apache-tomcat-8.5.37/conf/web.xml' : gruppe,
}
for path in restrictions:
    mod = restrictions[path]
    os.chmod(path, mod)

# shutil.rmtree('/home/lukas/apache-tomcat-8.5.37/webapps/docs')
# shutil.rmtree('/home/lukas/apache-tomcat-8.5.37/webapps/examples')

os.rename('/home/lukas/apache-tomcat-8.5.37/conf/logging.properties', 'home/lukas/apache-tomcat-8.5.37/webapps/examples/WEB-INF/classes/logging.properties') 

# os.rename('/home/lukas/apache-tomcat-8.5.37/webapps/host-manager/manager.xml', '/home/lukas/apache-tomcat-8.5.37/webapps/host-manager/neuername.xml')
# os.rename('/home/lukas/apache-tomcat-8.5.37/webapps/manager', '/home/lukas/apache-tomcat-8.5.37/webapps/nochmalanders')