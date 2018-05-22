#pragma once
#include <QWidget>

class HexView : public QWidget
{
	public:
		HexView(QString filePath, QWidget *parent = 0);
};
