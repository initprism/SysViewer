#pragma once


#include <qabstractscrollarea.h>
#include <qbuffer.h>

namespace HexLib {
	class HexLib : public QAbstractScrollArea
	{
		Q_OBJECT
	public:
		HexLib(QWidget* parent = 0);
		~HexLib();

		void setData(const QByteArray &ba);
		bool setData(QIODevice &device);
		QByteArray data(qint64 pos = 0, qint64 count = -1);

	protected:
		void paintEvent(QPaintEvent *);
		void resizeEvent(QResizeEvent *);

	private:
		void adjustContent();
		void init();

		int addressWidth();
		int hexWidth();
		int asciiWidth();

		int nBlockAddress;
		int mBytesPerLine;

		int pxWidth;
		int pxHeight;

		qint64 startPos;
		qint64 endPos;

		int nRowsVisible;

		QBuffer buffer;
		QIODevice *ioDevice;
		qint64 size;
		
		QByteArray dataVisible;
		QByteArray dataHex;
	};
};