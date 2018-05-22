#include <QHBoxLayout>
#include <QFile>
#include "hexview.h"
#include "HexLib\HexLib.h"

HexView::HexView(QString filePath, QWidget *parent) : QWidget(parent)
{
	// --------------------- load hex info ----------------------- //
	QFile *file = new QFile();
	file->setFileName(filePath);

	HexLib::HexLib *hex = new HexLib::HexLib(this);
	hex->setData(*file);

	// --------------------- layout info ----------------------- //
	QHBoxLayout *hbox = new QHBoxLayout(this);
	hbox->addWidget(hex);
	hbox->setContentsMargins(0, 0, 0, 0);

	// --------------------- post process ----------------------- //
	file->close();
}
