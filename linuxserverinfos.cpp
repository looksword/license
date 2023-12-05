#include "linuxserverinfos.h"

std::vector<std::string> getIpAddress() {
    std::vector<std::string> result;

    // 获取所有网络接口
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();

    // 遍历所有网络接口
    for(const QNetworkInterface& interface : interfaces) {
        //遍历网络接口的所有IP地址
        QList<QNetworkAddressEntry> entries = interface.addressEntries();
        for(const QNetworkAddressEntry& entry : entries) {
            // 获取并保存IP地址
            std::string ip = entry.ip().toString().toLower().toStdString();
            //查找是否已经存在相同IP，不存在则插入
            if(std::find(result.begin(), result.end(), ip) == result.end()) {
                result.push_back(ip);
            }
        }
    }

    return result;
}

std::vector<std::string> getMacAddress() {
    std::vector<std::string> result;

    // 获取所有网络接口
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();

    // 遍历所有网络接口
    for(const QNetworkInterface& interface : interfaces) {

        QList<QNetworkAddressEntry> allEntries = interface.addressEntries();
        for(const QNetworkAddressEntry &entry : allEntries)
        {
            QHostAddress hostAddress = entry.ip();
            if(!hostAddress.isLoopback() && !hostAddress.isLinkLocal() && !hostAddress.isMulticast())
            {
                // 获取并保存MAC地址
                QString mac = interface.hardwareAddress();
                if (!mac.isEmpty()) {
                    // 转化为小写
                    mac = mac.toLower().replace(":","");
                    std::string newmac = mac.toStdString();
                    // 查找是否已经存在相同Mac地址，不存在则插入
                    if (std::find(result.begin(), result.end(), newmac) == result.end()) {
                        result.push_back(mac.toStdString());
                    }
                }
            }
        }
    }

    return result;
}

std::string getCPUSerial() {
    // 存放CPU序列号
    QString serialNumber = "";

    // 使用QProcess对象来运行dmidecode命令获取CPU序列号
    QProcess process;
#ifdef Q_OS_LINUX
    process.start("/bin/bash", QStringList() << "-c" << "dmidecode -t processor | grep 'ID' | awk -F ':' '{print $2}' | head -n 1");
#endif
#ifdef Q_OS_WIN
    process.start("wmic cpu get processorid");
#endif
    process.waitForFinished();

    // 获取命令的输出
    QString output(process.readAllStandardOutput());

    // 去除多余的空格和换行符
#ifdef Q_OS_LINUX
    serialNumber = output.trimmed();
#endif
#ifdef Q_OS_WIN
    QStringList outputs = output.split("\r\n",QString::SplitBehavior::SkipEmptyParts);
    if(outputs.length() > 1)
    {
        serialNumber = outputs[1].trimmed();
    }
#endif

    return serialNumber.toStdString();
}


std::string getMainBoardSerial() {
    // 存放主板序列号
    QString serialNumber;

    // 使用QProcess对象来运行dmidecode命令获取主板序列号
    QProcess process;
#ifdef Q_OS_LINUX
    process.start("/bin/bash", QStringList() << "-c" << "dmidecode | grep 'Serial Number' | awk -F ':' '{print $2}' | head -n 1");
#endif
#ifdef Q_OS_WIN
    process.start("wmic baseboard get serialnumber");
#endif
    process.waitForFinished();

    // 获取命令的输出
    QString output(process.readAllStandardOutput());

    // 去除多余的空格和换行符
#ifdef Q_OS_LINUX
    serialNumber = output.trimmed();
#endif
#ifdef Q_OS_WIN
    QStringList outputs = output.split("\r\n",QString::SplitBehavior::SkipEmptyParts);
    if(outputs.length() > 1)
    {
        serialNumber = outputs[1].trimmed();
    }
#endif

    return serialNumber.toStdString();
}
