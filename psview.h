#include <QWidget>

QT_BEGIN_NAMESPACE
class QLineEdit; //forward declarations
class QTableWidget;
QT_END_NAMESPACE

class PsView : public QWidget
{
	Q_OBJECT
	public:
		PsView( QWidget *parent = 0);
		QLineEdit *echoLineEdit;

	private:
		QTableWidget * pst;
		QString dPath;

	private slots:
		void dllOpen();
		void dllInjection();
};