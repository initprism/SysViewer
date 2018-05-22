#pragma once
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include "PeLib/PeLib.h"


std::string tabnames[] = { "Export Directory",
"Import Directory",
"Resource Directory",
"Exception Directory",
"Security Directory",
"BaseReloc Directory",
"Debug Directory",
"Architecture Directory",
"GlobalPtr Directory",
"Tls Directory",
"LoadConfig Directory",
"BoundImport Directory",
"IAT Directory",
"DelayImport Directory",
"ComDescriptor Directory",
"Reserved Directory"
};

template<typename T>
std::string toString(T x, char f = '0')
{
	std::stringstream ss;
	ss << std::setw(sizeof(T) * 2) << std::setfill(f) << std::hex << std::uppercase << x;
	return ss.str();
}

template<>
std::string toString<PeLib::byte>(PeLib::byte x, char f)
{
	std::stringstream ss;
	ss << std::setw(2) << std::setfill(f) << std::hex << std::uppercase << (int)x;
	return ss.str();
}

std::string formatOutput(const std::string& text, const std::string& val, const std::string& pad = "", unsigned int maxsize = 70)
{
	std::stringstream ss;
	ss << text;
	ss << std::setw(maxsize - text.length()) << std::setfill(' ') << ":";
	ss << val;
	//ss << pad << text << std::setw(maxsize - (int)text.length() - (int)val.length() - (int)pad.length()) << std::setfill(' ') << "";
	//ss << val;
	return ss.str();
}

QString formatQStringOutput(const std::string& text, const std::string& val, const std::string& pad = "", unsigned int maxsize = 70)
{
	std::string s = formatOutput(text, val);
	return	QString::fromStdString(s);
}

void setTableItem(QTableWidget* tw, int row, char* s1, std::string& s2, char* s3 = "")
{
	tw->setItem(row, 0, new QTableWidgetItem(s1));
	tw->setItem(row, 1, new QTableWidgetItem(s2.c_str()));
	tw->setItem(row, 2, new QTableWidgetItem(s3));
}


void setTableItem(QTableWidget* tw, int row, std::string&  s1, char *s2, std::string& s3, char* s4 = "")
{
	tw->setItem(row, 0, new QTableWidgetItem(s1.c_str()));
	tw->setItem(row, 1, new QTableWidgetItem(s2));
	tw->setItem(row, 2, new QTableWidgetItem(s3.c_str()));
	tw->setItem(row, 3, new QTableWidgetItem(s4));
}
