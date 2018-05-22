#pragma once
#include <QMainWindow>

QT_BEGIN_NAMESPACE
class PeView; //forward declarations
class HexView;
class PsView;
class DllView;
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
	Q_OBJECT
public:
	MainWindow(QWidget *parent = 0);

private:
	QString filePath;
	PeView* peView;
	HexView* hexView;
	PsView* psView;
	DllView* dllView;

	private slots:
	void onActionOpen();
	void onActionAbout();
};
