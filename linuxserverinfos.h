#ifndef LINUXSERVERINFOS_H
#define LINUXSERVERINFOS_H


#include <QProcess>
#include <QString>
#include <QNetworkInterface>

std::vector<std::string> getIpAddress();

std::vector<std::string> getMacAddress();

std::string getCPUSerial();

std::string getMainBoardSerial();

#endif // LINUXSERVERINFOS_H
