#!/usr/bin/python3

from shutil import copyfile, rmtree

# Global Variables
# Path to the apache root directory
catalinaHome = ""  # /home/lukas/apache-tomcat-8.5.37/
catalinaHomeBackup = catalinaHome + "backup/"
managerApplicationUtilized = False

# Global Functions
def backupFiles(sourceRoot, targetRoot, path):
    copyfile(sourceRoot + path,
             targetRoot + path)


# 1 Remove Extraneous Resources
# 1.1 Remove extraneous files and directories (Scored)
backupFiles(catalinaHome, catalinaHomeBackup, 'webapps/docs')
backupFiles(catalinaHome, catalinaHomeBackup, 'webapps/examples')
rmtree(catalinaHome + 'webapps/docs')
rmtree(catalinaHome + 'webapps/examples')

if not managerApplicationUtilized:
    backupFiles(catalinaHome, catalinaHomeBackup, 'webapps/host-manager')
    backupFiles(catalinaHome, catalinaHomeBackup, 'webapps/manager')
    backupFiles(catalinaHome, catalinaHomeBackup,
                'conf/Catalina/localhost/manager.xml')
    rmtree(catalinaHome + 'webapps/host-manager')
    rmtree(catalinaHome + 'webapps/manager')
    rmtree(catalinaHome + 'conf/Catalina/localhost/manager.xml')
