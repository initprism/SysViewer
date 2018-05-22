#include <QApplication>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>
#include <QTextStream>
#include <QMenu>
#include <QMenuBar>
#include <QPixmap>
#include <QToolBar>
#include <QDir>
#include <QMessageBox>
#include <QSplitter>
#include <QStatusBar>
#include "mainwindow.h"
#include "peview.h"
#include "hexview.h"
#include "psview.h"

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent)
{
	// --------------------- menu info ----------------------- //
	QPixmap mainIcon("Resources/icon/open.png");
	QAction *openAction = new QAction(mainIcon, "&Open", this);
	QAction *quitAction = new QAction("&Quit", this);
	QAction *aboutAction = new QAction("&About", this);

	QMenu *file;
	file = menuBar()->addMenu("&File");
	file->addAction(openAction);
	file->addSeparator();
	file->addAction(quitAction);
	
	QMenu *help;
	help = menuBar()->addMenu("&Help");
	help->addAction(aboutAction);

	// --------------------- toolbar info ----------------------- //
	QToolBar *toolbar = addToolBar("main toolbar");
	QAction *openActionInToolbar = toolbar->addAction(QIcon(mainIcon), "Open File");
	
	// --------------------- shortcut info ----------------------- //
	openAction->setShortcut(tr("CTRL+O"));
	quitAction->setShortcut(tr("ALT+F4"));

	// --------------------- css & optional info ----------------------- //
	setWindowTitle("AdvanceSysView. GNU Dept. CS 2017080066");
	setWindowIcon(mainIcon);
	statusBar();

	setStyleSheet("background-color : rgb(39, 39, 39); color : white");
	file->setStyleSheet("background-color : rgb(53,53,53)");
	help->setStyleSheet("background-color : rgb(53,53,53)");
	toolbar->setStyleSheet("background-color : rgb(60, 60, 60)");

	openAction->setStatusTip(tr("Open new file"));
	aboutAction->setStatusTip(tr("About"));

	statusBar()->setStyleSheet("background-color : rgb(60, 60, 60)");
	statusBar()->showMessage(tr("ready"));

	// --------------------- layout info ----------------------- //
	setContentsMargins(0, 0, 0, 0);
	setMinimumSize(300, 150);

	// --------------------- singal ----------------------- //
	connect(openAction, &QAction::triggered, this, &MainWindow::onActionOpen);
	connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);
	connect(aboutAction, &QAction::triggered, this, &MainWindow::onActionAbout);

	connect(openActionInToolbar, &QAction::triggered, this, &MainWindow::onActionOpen);

	// --------------------- post process ----------------------- //

}

void MainWindow::onActionOpen()
{
	// --------------------- open action info ----------------------- //
	//for specific extension//
	QString filter = "Executable (*.exe) ;; Dynamic Link Library (*.dll) ;; System (*.sys) ;; ActiveX Control (*.ocx) ;; Control Panel Extension (*cpl) ;; Screnn Saver (*.scr) ;; Object (*.obj) ;; Symbol (*.dbg) ;; Library (*.lib) ;; Type Library(*.tlb, *.olb) ;; All Files (*.*) ";
	
	filePath = QFileDialog::getOpenFileName(this, "Open File", QDir::homePath(), filter);
	if (!filePath.isEmpty()) {
		// --------------------- widget info ----------------------- //
		peView = new PeView(filePath,this);
		hexView = new HexView(filePath);
		psView = new PsView();

		// --------------------- layout info ----------------------- //
		QSplitter *splitter1 = new QSplitter(Qt::Horizontal, this);
		QSplitter *splitter2 = new QSplitter(Qt::Vertical, this);

		splitter1->addWidget(peView);
		splitter1->addWidget(hexView);


		splitter2->addWidget(splitter1);
		splitter2->addWidget(psView);

		setCentralWidget(splitter2);

		QList<int> lst = splitter1->sizes();	// split position
		lst.replace(0, this->width() / 0.3);
		lst.replace(1, this->width() / 0.7);
		splitter1->setSizes(lst);
		splitter2->setSizes(lst);

		// --------------------- css & optional info ----------------------- //
		splitter1->setStyleSheet("QSplitter::handle{background : rgb(60, 60, 60)};");
		splitter2->setStyleSheet("QSplitter::handle{background : rgb(60, 60, 60)};");
		
		setWindowTitle(QFileInfo(filePath).fileName() + "     AdvanceSysView. GNU Dept. CS 2017080066");
		statusBar()->showMessage(QFileInfo(filePath).fileName());
		// --------------------- post process ----------------------- //
		
	}
}

void MainWindow::onActionAbout()
{
	// --------------------- messagebox info ----------------------- //
	QMessageBox messagebox;
	const QString content = "<p style='text-align: center;'><img src='Resources/icon/open.png' alt = ''> </p> <p style='text-align: center;'><strong>AdvanceSysView</strong></p> <p style='text-align: center;'>Version 0x01</p> <p style='text-align: center;'>GNU Dept. CS 2017080066</p> <p style='text-align: center;'>Copyright &copy; DooHwan Kim, 2018 All rights reserved.</p><p style='text-align: center;>&nbsp;</p>";
	messagebox.setInformativeText(content);
	messagebox.setWindowTitle("About");
	messagebox.setStandardButtons(QMessageBox::Ok);
	messagebox.setDefaultButton(QMessageBox::Ok);
	messagebox.setFont(QFont::QFont("", 11, QFont::Normal));
	messagebox.setWindowIcon(QPixmap("Resources/icon/open.png"));

	// --------------------- layout info ----------------------- //
	QGridLayout *lay = messagebox.findChild<QGridLayout *>();
	QMargins margins = lay->contentsMargins();
	margins.setRight(40);
	lay->setContentsMargins(margins);

	// --------------------- css & optional info ----------------------- //
	messagebox.setStyleSheet("background-color : rgb(39, 39, 39); color : white; align : center");

	// --------------------- post process ----------------------- //
	messagebox.exec();
}
