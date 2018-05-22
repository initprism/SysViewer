#include <QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
	QApplication app(argc, argv);
	MainWindow window;
	window.resize(850, 420);
	window.show();
	return app.exec();
}
