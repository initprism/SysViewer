#pragma once
#include <QWidget>

QT_BEGIN_NAMESPACE 
class QTreeView; //forward declarations
class QStandardItemModel;
class QItemSelection;
class QStackedWidget;
class QFile;
QT_END_NAMESPACE

class PeView : public QWidget
{
	Q_OBJECT
public:
	PeView(QString filePath, QWidget *parent = 0);

private:
	QTreeView * treeView;
	QStandardItemModel *standardModel;
	QStackedWidget* stackedWidget;
	QFile *hex_f;
	int numberOfSection;

	private slots:
	void selectionChangedSlot(const QItemSelection & newSelection, const QItemSelection & oldSelection);
};
