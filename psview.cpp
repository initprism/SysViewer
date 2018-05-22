#include <QTableWidget>
#include <QHeaderView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <iostream>
#include <vector>
#include <utility>
#include <QLineEdit>
#include <QPushButton>
#include <string>
#include <QString>
#include <QFileDialog>
#include "PsLib\PsLib.h"
#include "DllLib\DllLib.h"
#include "psview.h"

PsView::PsView(QWidget *parent) : QWidget(parent)
{
	// --------------------- load prosecess ----------------------- //
	pslib::PsLib* ps = new pslib::PsLib();
	std::vector<std::pair<std::string, int>> psl1 = ps->processs1;
	std::vector<std::string> psl2 = ps->processs2;

	// --------------------- Process Table info ----------------------- //
	pst = new QTableWidget;
	pst->setRowCount(ps->getNumOfPro());
	pst->setColumnCount(3);
	pst->setHorizontalHeaderLabels(QStringList() << "Name" << "PID" << "Path");
	pst->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:transparent}");
	pst->verticalHeader()->setVisible(false);
	pst->setShowGrid(false);
	pst->setEditTriggers(QAbstractItemView::NoEditTriggers);
	pst->setSelectionBehavior(QAbstractItemView::SelectRows);
	//pst->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	pst->setStyleSheet("font-size : 13px");

	for (int i = 0; i < psl1.size(); i++) {
		pst->setItem(i, 0, new QTableWidgetItem(psl1[i].first.c_str()));
		pst->setItem(i, 1, new QTableWidgetItem(QString::number(psl1[i].second)));
		pst->setItem(i, 2, new QTableWidgetItem(psl2[i].c_str()));
	}
	pst->horizontalHeader()->setStretchLastSection(true);

	// --------------------- Dll view info ----------------------- //
	QWidget *dllView = new QWidget();
	echoLineEdit = new QLineEdit();
	echoLineEdit->setAlignment(Qt::AlignTop | Qt::AlignLeft);

	QPushButton *Pbutton1 = new QPushButton();
	Pbutton1->setText(" Select DLL ");

	QPushButton *Pbutton2 = new QPushButton();
	Pbutton2->setText("   Inject   ");
	// --------------------- layout info ----------------------- //
	QHBoxLayout *hboxWidget = new QHBoxLayout(this);
	hboxWidget->addWidget(echoLineEdit);
	hboxWidget->addWidget(Pbutton1);
	dllView->setLayout(hboxWidget);

	QVBoxLayout *vboxWidget = new QVBoxLayout(this);
	vboxWidget->addWidget(dllView);
	vboxWidget->addWidget(pst);
	vboxWidget->addWidget(Pbutton2);
	vboxWidget->setContentsMargins(0, 0, 0, 0);
	setLayout(hboxWidget);

	// --------------------- css & optional info ----------------------- //
	
	Pbutton1->setStyleSheet("background-color : rgb(48, 48, 48); color : white; font-size : 13px");
	Pbutton2->setStyleSheet("background-color : rgb(48, 48, 48); color : white; font-size : 13px");
	echoLineEdit->setStyleSheet("background-color : white; color : rgb(48, 48, 48); font-size : 13px ");

	// --------------------- post process ----------------------- //
	connect(Pbutton1, SIGNAL(clicked()), this, SLOT(dllOpen()));
	connect(Pbutton2, SIGNAL(clicked()), this, SLOT(dllInjection()));
}

void PsView::dllOpen()
{
	QString filter = "Dynamic Link Library (*.dll)";
	dPath = QFileDialog::getOpenFileName(this, "Open DLL", QDir::homePath(), filter);
	if (!dPath.isEmpty()) {
		echoLineEdit->setText(dPath);
	}
}



void PsView::dllInjection()
{

	DWORD dwProcessId = pst->item(pst->currentRow(), 1)->text().toInt();

	if (!echoLineEdit->text().isEmpty()) {
		wchar_t *strProcName = new wchar_t[dPath.size() + 1 ];

		int len = dPath.toWCharArray(strProcName);
		strProcName[len] = 0;

		//wprintf(TEXT("%s %d"), strProcName, dwProcessId);

		DllLib::DllLib dll(strProcName, dwProcessId);
		dll.SetSePrivilege();
		dll.injectDll();
	}
}